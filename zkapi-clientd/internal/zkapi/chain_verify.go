package zkapi

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// The packaged payment RPC is a third party. Before a note secret leaves this
// process, a failed deposit is retired, or a withdrawal closes local state,
// its claims are checked against the operator indexer's tree snapshot. The
// snapshot is the same payload for every caller, so the indexer never learns
// which note is ours; Go recomputes the expected leaf with zkAPI Poseidon.
// Lag or missing data is pending; disagreement is a non-terminal conflict.

const notesSelector = "0x9f18e4ed" // notes(uint32)

const (
	noteUninitialized uint8 = iota
	noteActive
	notePendingWithdrawal
	noteClosed
)

const (
	maxSafeNoteAmount = 9_007_199_254_740_991
	// About 450,000 leaves; a snapshot is the whole leaf vector.
	indexerSnapshotLimit = 32 << 20
	// The vault rounds expiry up to whole days: ceil((t + noteTtl) / 1 day).
	vaultExpiryBucket = 24 * 60 * 60
	// A deposit's calldata can only match an empty slot at or shortly after
	// the one it was built for (after closes restored identical siblings).
	depositRevertScanSlots  = 64
	depositRevertMaxBuckets = 64
)

var (
	errDepositVerificationPending    = errors.New("the deposit is mined; waiting for the zkAPI indexer to confirm it before activation")
	errDepositVerificationConflict   = errors.New("the payment RPC, the vault state, and the zkAPI indexer disagree about this deposit; its private note was not activated")
	errRevertVerificationPending     = errors.New("waiting for the zkAPI indexer to confirm the revert")
	errWithdrawalVerificationPending = errors.New("the withdrawal is final on Ethereum; waiting for the vault state and the zkAPI indexer to confirm the note is closed")
)

const conflictGuidance = " Checking again re-verifies automatically. If this persists, compare the transaction on a block explorer and run zkapi-clientd config --menu, then choose repair."

type vaultNoteState struct {
	Commitment string // 0x + 64 lowercase hex
	Amount     uint64
	ExpiryTs   uint64
	Status     uint8
}

// blockAtHash is an EIP-1898 block parameter: the read fails, rather than
// silently using another fork, when the RPC's block is not canonical.
func blockAtHash(hash string) map[string]any {
	return map[string]any{"blockHash": strings.ToLower(hash), "requireCanonical": true}
}

func (h *FundingHandler) vaultNote(ctx context.Context, config fundingConfig, id uint32, block any) (vaultNoteState, error) {
	var encoded string
	call := map[string]string{"to": config.Contract, "data": fmt.Sprintf("%s%064x", notesSelector, id)}
	if err := h.addressRPC(ctx, config, "eth_call", []any{call, block}, &encoded); err != nil {
		return vaultNoteState{}, err
	}
	return decodeVaultNote(encoded)
}

// vaultNoteAtReceipt reads notes(id) at the receipt's own canonical block.
// Full nodes keep state only for recent blocks, so once that block is final
// the finalized block, also read by hash and canonical only, is used instead.
func (h *FundingHandler) vaultNoteAtReceipt(ctx context.Context, config fundingConfig, id uint32, receiptBlock uint64, receiptHash string) (vaultNoteState, error) {
	note, err := h.vaultNote(ctx, config, id, blockAtHash(receiptHash))
	if err == nil {
		return note, nil
	}
	finalized, hash, finalErr := h.finalizedBlock(ctx, config)
	if finalErr != nil || finalized < receiptBlock {
		return vaultNoteState{}, err
	}
	return h.vaultNote(ctx, config, id, blockAtHash(hash))
}

func (h *FundingHandler) finalizedBlock(ctx context.Context, config fundingConfig) (uint64, string, error) {
	var header struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if err := h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{"finalized", false}, &header); err != nil {
		return 0, "", err
	}
	number, err := addressHexUint(header.Number)
	if err != nil || !number.IsUint64() || !isHex(header.Hash, 32) {
		return 0, "", errors.New("invalid finalized block from the payment RPC")
	}
	return number.Uint64(), strings.ToLower(header.Hash), nil
}

// decodeVaultNote accepts exactly notes(uint32)'s four static words:
// (bytes32 commitment, uint128 depositAmount, uint64 expiryTs, uint8 status).
func decodeVaultNote(encoded string) (vaultNoteState, error) {
	invalid := errors.New("invalid vault note state")
	if len(encoded) != 2+4*64 || !strings.HasPrefix(encoded, "0x") {
		return vaultNoteState{}, invalid
	}
	raw, err := hex.DecodeString(encoded[2:])
	if err != nil {
		return vaultNoteState{}, invalid
	}
	zero := func(bytes []byte) bool {
		for _, b := range bytes {
			if b != 0 {
				return false
			}
		}
		return true
	}
	amount := binary.BigEndian.Uint64(raw[56:64])
	if !zero(raw[32:56]) || amount > maxSafeNoteAmount || !zero(raw[64:88]) || !zero(raw[96:127]) || raw[127] > noteClosed {
		return vaultNoteState{}, invalid
	}
	return vaultNoteState{Commitment: "0x" + hex.EncodeToString(raw[:32]), Amount: amount, ExpiryTs: binary.BigEndian.Uint64(raw[88:96]), Status: raw[127]}, nil
}

type treeSnapshot struct {
	Root        *big.Int
	NextNoteID  uint32
	Leaves      []string
	BlockNumber uint64
	BlockHash   string
}

// leaf returns the indexer's current leaf for id. present is false only when
// the snapshot has no such note; a malformed leaf is an error.
func (s *treeSnapshot) leaf(id uint32) (value *big.Int, present bool, err error) {
	if uint64(id) >= uint64(len(s.Leaves)) {
		return nil, false, nil
	}
	value, ok := parseFieldElement(s.Leaves[id])
	if !ok {
		return nil, true, errors.New("invalid zkAPI indexer leaf")
	}
	return value, true, nil
}

// indexerSnapshot reads the packaged indexer's whole-tree snapshot through the
// configured transport, with no credentials and no redirects. Bodies are
// never reflected. A snapshot without block metadata (an older indexer) can
// never be evidence: its applied block is unknown.
func (h *FundingHandler) indexerSnapshot(ctx context.Context, config fundingConfig) (*treeSnapshot, error) {
	unavailable := errors.New("the zkAPI indexer snapshot is unavailable")
	if config.Indexer == "" {
		return nil, unavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(config.Indexer, "/")+"/v1/tree/snapshot", nil)
	if err != nil {
		return nil, unavailable
	}
	req.Header.Set("Accept", "application/json")
	response, err := h.client.inference.Do(req)
	if err != nil {
		return nil, unavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, indexerSnapshotLimit+1))
	if err != nil || len(raw) > indexerSnapshotLimit || response.StatusCode != http.StatusOK {
		return nil, unavailable
	}
	var wire struct {
		Root        string   `json:"root"`
		NextNoteID  *uint32  `json:"next_note_id"`
		Leaves      []string `json:"leaves"`
		BlockNumber *uint64  `json:"block_number"`
		BlockHash   string   `json:"block_hash"`
	}
	invalid := errors.New("invalid zkAPI indexer snapshot")
	if json.Unmarshal(raw, &wire) != nil || wire.NextNoteID == nil || uint64(len(wire.Leaves)) != uint64(*wire.NextNoteID) {
		return nil, invalid
	}
	root, ok := parseFieldElement(wire.Root)
	if !ok {
		return nil, invalid
	}
	for _, leaf := range wire.Leaves {
		if _, ok := parseFieldElement(leaf); !ok {
			return nil, invalid
		}
	}
	if wire.BlockNumber == nil || !isHex(wire.BlockHash, 32) {
		return nil, errors.New("the zkAPI indexer snapshot has no block identity; the indexer must be upgraded")
	}
	return &treeSnapshot{Root: root, NextNoteID: *wire.NextNoteID, Leaves: wire.Leaves, BlockNumber: *wire.BlockNumber, BlockHash: strings.ToLower(wire.BlockHash)}, nil
}

// confirmedSnapshot is an indexer view that has applied minBlock, on the
// chain the payment RPC also reports as canonical. A lagging or forked view
// is pending, never a verdict.
func (h *FundingHandler) confirmedSnapshot(ctx context.Context, config fundingConfig, minBlock uint64) (*treeSnapshot, error) {
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return nil, err
	}
	if snapshot.BlockNumber < minBlock {
		return nil, errors.New("the zkAPI indexer has not reached the receipt block")
	}
	var header struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if err := h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{fmt.Sprintf("0x%x", snapshot.BlockNumber), false}, &header); err != nil {
		return nil, err
	}
	number, err := addressHexUint(header.Number)
	if err != nil || !number.IsUint64() || number.Uint64() != snapshot.BlockNumber || !strings.EqualFold(header.Hash, snapshot.BlockHash) {
		return nil, errors.New("the zkAPI indexer view is not on the payment RPC's canonical chain")
	}
	return snapshot, nil
}

// corroborateDeposit binds a validated deposit receipt to a note only when the
// vault, read at the receipt's own canonical block, and the indexer snapshot
// (at or after that block) both hold exactly this deposit at the receipt's
// note ID. Called before the companion receives the note secret.
func (h *FundingHandler) corroborateDeposit(ctx context.Context, config fundingConfig, record depositRecord, receipt ethReceipt, noteID uint32, expiry uint64) (*depositBinding, error) {
	pending := func(reason string) error { return fmt.Errorf("%w (%s)", errDepositVerificationPending, reason) }
	conflict := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errDepositVerificationConflict, fmt.Sprintf(format, args...))
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return nil, pending("the payment RPC network check is unavailable")
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() || !isHex(receipt.BlockHash, 32) {
		return nil, pending("the receipt has no block identity")
	}
	commitment, ok := parseFieldElement(record.Commitment)
	if !ok {
		return nil, errors.New("invalid pending commitment")
	}
	note, err := h.vaultNoteAtReceipt(ctx, config, noteID, block.Uint64(), receipt.BlockHash)
	if err != nil {
		return nil, pending("the vault state at the receipt block is unavailable")
	}
	if note.Status == noteUninitialized {
		return nil, pending("the vault does not show the note yet")
	}
	if note.Status != noteActive || !strings.EqualFold(note.Commitment, "0x"+addressABIWord(record.Commitment)) || note.Amount != record.Amount || note.ExpiryTs != expiry {
		return nil, conflict("vault note %d does not hold this deposit", noteID)
	}
	snapshot, err := h.confirmedSnapshot(ctx, config, block.Uint64())
	if err != nil {
		return nil, pending(err.Error())
	}
	leaf, present, err := snapshot.leaf(noteID)
	if err != nil {
		return nil, pending(err.Error())
	}
	if !present || leaf.Cmp(noteLeaf(noteID, commitment, record.Amount, expiry)) != 0 {
		return nil, conflict("the zkAPI indexer does not show this deposit at note %d", noteID)
	}
	return &depositBinding{NoteID: noteID, ExpiryTs: expiry, BlockNumber: block.Uint64(), BlockHash: strings.ToLower(receipt.BlockHash), IndexerBlock: snapshot.BlockNumber}, nil
}

// bindDepositPath refreshes the companion's empty-leaf witness immediately
// before signing and binds it to the slot it proves: the siblings must hash
// an empty leaf at the snapshot's next_note_id to the snapshot root. The slot
// is saved with the note record before the transaction exists, so a later
// reported revert can be checked against what actually happened there.
func (h *FundingHandler) bindDepositPath(ctx context.Context, config fundingConfig, deposit *depositRecord) (string, error) {
	path, err := h.depositPath(ctx)
	if err != nil {
		return "", err
	}
	encoded, _ := json.Marshal(path)
	var refreshed struct {
		ZeroPath []string `json:"zero_path"`
	}
	if json.Unmarshal(encoded, &refreshed) != nil || len(refreshed.ZeroPath) != merkleDepth {
		return "", errors.New("invalid refreshed deposit path")
	}
	siblings := make([]*big.Int, merkleDepth)
	for i, sibling := range refreshed.ZeroPath {
		value, ok := parseFieldElement(sibling)
		if !ok {
			return "", errors.New("invalid refreshed deposit path")
		}
		siblings[i] = value
	}
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return "", fmt.Errorf("%v; no deposit was signed", err)
	}
	if merkleRoot(snapshot.NextNoteID, new(big.Int), siblings).Cmp(snapshot.Root) != 0 {
		return "", errors.New("the deposit witness does not match the zkAPI indexer's current tree; no deposit was signed, retry")
	}
	data := "0xc588341c" + addressABIWord(deposit.Commitment) + fmt.Sprintf("%064x", deposit.Amount)
	for _, sibling := range refreshed.ZeroPath {
		data += addressABIWord(sibling)
	}
	calldata, err := hex.DecodeString(data[2:])
	if err != nil || len(calldata) != 4+34*32 {
		return "", errors.New("invalid deposit call data")
	}
	deposit.ZeroPath = refreshed.ZeroPath
	deposit.Slot = &depositSlot{NoteID: snapshot.NextNoteID, PathSHA256: depositPathDigest(calldata), PreparedAt: time.Now().Unix()}
	if err := h.save(*deposit); err != nil {
		return "", err
	}
	return data, nil
}

func depositPathDigest(calldata []byte) string {
	digest := sha256.Sum256(calldata[68:])
	return "0x" + hex.EncodeToString(digest[:])
}

// signedDepositSlot returns the recorded slot only when it describes the
// exact zero path inside this signed deposit transaction.
func signedDepositSlot(deposit *depositRecord, saved *addressTransaction) (*depositSlot, bool) {
	if deposit == nil || deposit.Slot == nil || saved == nil || saved.Kind != "deposit" {
		return nil, false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(saved.Raw, "0x"))
	var tx types.Transaction
	if err != nil || tx.UnmarshalBinary(raw) != nil || len(tx.Data()) != 4+34*32 || hex.EncodeToString(tx.Data()[:4]) != "c588341c" {
		return nil, false
	}
	if !strings.EqualFold(depositPathDigest(tx.Data()), deposit.Slot.PathSHA256) {
		return nil, false
	}
	return deposit.Slot, true
}

// checkDepositRevert decides whether a finalized failed deposit may be retired.
// A hostile RPC can report a revert for a deposit that actually created our
// note; retiring it would reuse the note secret in a second deposit. The
// indexer must show that this note did not land where the signed calldata
// could apply. Foreign deposits reusing the public commitment with another
// amount never match our leaf, so they cannot block a genuine retry. Deposits
// signed before slots were recorded keep the previous behaviour.
func (h *FundingHandler) checkDepositRevert(ctx context.Context, config fundingConfig, deposit *depositRecord, saved *addressTransaction, receipt *addressReceipt) error {
	slot, ok := signedDepositSlot(deposit, saved)
	if !ok {
		return nil
	}
	commitment, ok := parseFieldElement(deposit.Commitment)
	if !ok {
		return errors.New("invalid pending commitment")
	}
	ttl, err := h.noteTTL()
	if err != nil {
		return err
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() {
		return errRevertVerificationPending
	}
	snapshot, err := h.confirmedSnapshot(ctx, config, block.Uint64())
	if err != nil {
		return fmt.Errorf("%w (%v)", errRevertVerificationPending, err)
	}
	if id, found := findDepositLeaf(snapshot, slot, commitment, deposit.Amount, ttl, time.Now().Unix()); found {
		return fmt.Errorf("%w: the zkAPI indexer records this private note's deposit at note %d; no replacement will be signed; run zkapi-clientd config --menu, then choose repair", errDepositVerificationConflict, id)
	}
	// Another leaf holds the slot, it was emptied, or it is still free. A
	// retry is rebuilt from the then-current tree: while the slot is free it
	// targets the same slot, so at most one of the two transactions can land,
	// and a late landing of this one is found by the next check or a rebind.
	return nil
}

// findDepositLeaf looks for exactly our leaf (commitment, amount and a
// day-bucketed expiry the vault could have assigned since the deposit was
// prepared) at the prepared slot and the few slots after it.
func findDepositLeaf(snapshot *treeSnapshot, slot *depositSlot, commitment *big.Int, amount, ttl uint64, now int64) (uint32, bool) {
	expiries := plausibleExpiries(slot.PreparedAt, now, ttl)
	end := uint64(slot.NoteID) + depositRevertScanSlots
	if end > uint64(snapshot.NextNoteID) {
		end = uint64(snapshot.NextNoteID)
	}
	for id := uint64(slot.NoteID); id < end; id++ {
		leaf, ok := parseFieldElement(snapshot.Leaves[id])
		if !ok || leaf.Sign() == 0 {
			continue
		}
		for _, expiry := range expiries {
			if leaf.Cmp(noteLeaf(uint32(id), commitment, amount, expiry)) == 0 {
				return uint32(id), true
			}
		}
	}
	return 0, false
}

// plausibleExpiries lists every bucketed expiry for a deposit mined between
// preparation and now, with one day of clock tolerance on each side.
func plausibleExpiries(preparedAt, now int64, ttl uint64) []uint64 {
	to := now + vaultExpiryBucket
	from := preparedAt - vaultExpiryBucket
	if oldest := to - depositRevertMaxBuckets*vaultExpiryBucket; from < oldest {
		from = oldest
	}
	if from > to {
		from = now - vaultExpiryBucket // A clock moved backwards since preparation.
	}
	if from < 0 {
		from = 0
	}
	bucket := func(t int64) uint64 {
		return (uint64(t) + ttl + vaultExpiryBucket - 1) / vaultExpiryBucket * vaultExpiryBucket
	}
	var expiries []uint64
	for expiry := bucket(from); expiry <= bucket(to); expiry += vaultExpiryBucket {
		expiries = append(expiries, expiry)
	}
	return expiries
}

func (h *FundingHandler) noteTTL() (uint64, error) {
	deployment, _, err := pinnedDeployment(h.client.config.Network)
	if err != nil {
		return 0, err
	}
	return deployment.NoteTTL, nil
}

// corroborateWithdrawalClosed requires the vault, read at the payout receipt's
// canonical block, and the indexer snapshot at or after it to show the
// reserved note closed before the companion deletes its note state. A forged
// payout receipt therefore never retires a live note; disagreement waits.
func (h *FundingHandler) corroborateWithdrawalClosed(ctx context.Context, config fundingConfig, noteID uint64, receipt *addressReceipt) error {
	pending := func(reason string) error { return fmt.Errorf("%w (%s)", errWithdrawalVerificationPending, reason) }
	if noteID > 0xffffffff {
		return errors.New("invalid withdrawal note")
	}
	if err := h.assertAddressChain(ctx, config); err != nil {
		return pending("the payment RPC network check is unavailable")
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() || !isHex(receipt.BlockHash, 32) {
		return pending("the receipt has no block identity")
	}
	note, err := h.vaultNoteAtReceipt(ctx, config, uint32(noteID), block.Uint64(), receipt.BlockHash)
	if err != nil || note.Status != noteClosed {
		return pending("the vault does not show the note closed at the payout block")
	}
	snapshot, err := h.confirmedSnapshot(ctx, config, block.Uint64())
	if err != nil {
		return pending(err.Error())
	}
	leaf, present, err := snapshot.leaf(uint32(noteID))
	if err != nil || !present || leaf.Sign() != 0 {
		return pending("the zkAPI indexer still shows the note in the tree")
	}
	return nil
}
