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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// The packaged payment RPC is a third party. Before a note secret leaves this
// process, a failed deposit is retired or retried, or a withdrawal closes
// local state, its claims are checked against the operator indexer's tree
// snapshot. The snapshot is the same payload for every caller, so the
// indexer never learns which note is ours; Go recomputes the expected leaf
// with zkAPI Poseidon. Lag or missing data is pending; disagreement is a
// non-terminal conflict.

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
	// The search for our leaf is bounded (see findDepositLeaf): it compares
	// this many occupied slots from a signed slot, over this many expiry days.
	depositRevertScanSlots  = 64
	depositRevertMaxBuckets = 64
	// A tree root response is a few hundred bytes.
	indexerRootLimit = 4 << 10
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

// indexerGet reads a public, parameterless route of the packaged indexer
// through the configured transport, with no credentials and no redirects.
// Every caller gets the same response, so the indexer never learns which
// note is ours. Bodies are never reflected.
func (h *FundingHandler) indexerGet(ctx context.Context, config fundingConfig, route string, limit int, timeout time.Duration) ([]byte, bool) {
	if config.Indexer == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(config.Indexer, "/")+route, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	response, err := h.client.inference.Do(req)
	if err != nil {
		return nil, false
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) > limit || response.StatusCode != http.StatusOK {
		return nil, false
	}
	return raw, true
}

// indexerRoot reads the identity of the indexer's current tree, its root and
// next_note_id, without the leaves. The root commits to every leaf.
func (h *FundingHandler) indexerRoot(ctx context.Context, config fundingConfig) (*big.Int, uint32, error) {
	raw, ok := h.indexerGet(ctx, config, "/v1/tree/root", indexerRootLimit, 5*time.Second)
	if !ok {
		return nil, 0, errors.New("the zkAPI indexer root is unavailable")
	}
	var wire struct {
		Root       string  `json:"root"`
		NextNoteID *uint32 `json:"next_note_id"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.NextNoteID == nil {
		return nil, 0, errors.New("invalid zkAPI indexer root")
	}
	root, valid := parseFieldElement(wire.Root)
	if !valid {
		return nil, 0, errors.New("invalid zkAPI indexer root")
	}
	return root, *wire.NextNoteID, nil
}

// indexerSnapshot reads the packaged indexer's whole-tree snapshot. A
// snapshot without block metadata (an older indexer) can never be evidence:
// its applied block is unknown.
func (h *FundingHandler) indexerSnapshot(ctx context.Context, config fundingConfig) (*treeSnapshot, error) {
	raw, ok := h.indexerGet(ctx, config, "/v1/tree/snapshot", indexerSnapshotLimit, 20*time.Second)
	if !ok {
		return nil, errors.New("the zkAPI indexer snapshot is unavailable")
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
//
// A deposit reported as reverted may have been withheld and still land, and
// a second deposit of this note would share its nullifier. So the same
// snapshot is searched for our leaf from the slot of every deposit of this
// note signed before, and nothing is signed when it is found. The new path
// and that search come from one tree. An earlier deposit missing from it
// cannot land beside the new one: the vault accepts each only against a
// tree without the other's leaf. An earlier deposit in it is found unless it
// lies outside findDepositLeaf's bounds. That happens only in two cases.
// After it landed, challengeEscapeWithdrawal restored 64 or more leaves
// between the slot it was built for and the slot it landed in. Or it landed
// about 63 or more days ago.
func (h *FundingHandler) bindDepositPath(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) (string, error) {
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
	signed := signedDepositSlots(deposit, record)
	if err := h.priorDepositConflict(snapshot, deposit, signed); err != nil {
		return "", err
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
	deposit.SignedSlots = signed
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
// indexer must show that this note did not land where the signed calldata of
// this or any earlier deposit of it could apply. Foreign deposits reusing the
// public commitment with another amount never match our leaf, so they cannot
// block a genuine retry. Deposits signed before slots were recorded keep the
// previous behaviour.
func (h *FundingHandler) checkDepositRevert(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord, receipt *addressReceipt) error {
	if _, ok := signedDepositSlot(deposit, record.Pending); !ok {
		return nil
	}
	block, err := addressHexUint(receipt.BlockNumber)
	if err != nil || !block.IsUint64() {
		return errRevertVerificationPending
	}
	snapshot, err := h.confirmedSnapshot(ctx, config, block.Uint64())
	if err != nil {
		return fmt.Errorf("%w (%v)", errRevertVerificationPending, err)
	}
	// Otherwise another leaf holds the slot, it was emptied, or it is still
	// free. The deposit may still land later, so a retry is searched for it
	// again, in the tree the retry is built from, before it is signed.
	return h.priorDepositConflict(snapshot, deposit, signedDepositSlots(deposit, record))
}

// landedDepositConflict reports this note's deposit found in the indexer's
// tree. Another deposit of the note would share its nullifier, so nothing
// more is signed; repair binds the note that landed.
func landedDepositConflict(id uint32) error {
	return fmt.Errorf("%w: the zkAPI indexer records this private note's deposit at note %d; no replacement will be signed; run zkapi-clientd config --menu, then choose repair", errDepositVerificationConflict, id)
}

// priorDepositConflict searches snapshot for our leaf from every slot a
// deposit of this note was signed for.
func (h *FundingHandler) priorDepositConflict(snapshot *treeSnapshot, deposit *depositRecord, slots []depositSlot) error {
	if len(slots) == 0 {
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
	if id, found := findSignedDepositLeaf(snapshot, slots, commitment, deposit.Amount, ttl, time.Now().Unix()); found {
		return landedDepositConflict(id)
	}
	return nil
}

// checkPriorDeposits searches the indexer's current tree the same way and
// fails closed: an unavailable indexer is an error. It decides whether a
// saved conflict about an earlier deposit is cleared. With no deposit of this
// note signed yet, it makes no request.
func (h *FundingHandler) checkPriorDeposits(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) error {
	slots := signedDepositSlots(deposit, record)
	if len(slots) == 0 {
		return nil
	}
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return err
	}
	return h.priorDepositConflict(snapshot, deposit, slots)
}

// priorDepositAdvice is the indexer tree that the last quote-time search ran
// on without finding any of the searched deposits.
type priorDepositAdvice struct {
	key  string
	root *big.Int
	next uint32
}

// advisePriorDeposits is the quote-time search, so that a user is not asked
// to fund a retry that approval would refuse. Approval searches the tree it
// signs from again and fails closed. So here only a deposit that is found
// refuses the quote, and an unavailable or older indexer does not. A tree
// that was already searched is not downloaded again: while a client polls
// quotes and waits for funds, each quote costs one small root read until
// the tree changes.
func (h *FundingHandler) advisePriorDeposits(ctx context.Context, config fundingConfig, record *addressFundingRecord, deposit *depositRecord) error {
	slots := signedDepositSlots(deposit, record)
	if len(slots) == 0 {
		return nil
	}
	ttl, err := h.noteTTL()
	if err != nil {
		return err
	}
	key := priorDepositKey(config, deposit, slots, ttl)
	if advice := h.priorAdvice; advice != nil && advice.key == key {
		root, next, err := h.indexerRoot(ctx, config)
		if err != nil || (root.Cmp(advice.root) == 0 && next == advice.next) {
			return nil
		}
	}
	snapshot, err := h.indexerSnapshot(ctx, config)
	if err != nil {
		return nil
	}
	if err := h.priorDepositConflict(snapshot, deposit, slots); err != nil {
		h.priorAdvice = nil
		return err
	}
	h.priorAdvice = &priorDepositAdvice{key: key, root: snapshot.Root, next: snapshot.NextNoteID}
	return nil
}

// priorDepositKey names what a search verdict depends on besides the tree and
// the time. Over time the expiry window only gains days after the search,
// when no leaf of an unchanged tree can have landed, and drops older ones.
// So a verdict that found nothing still holds while the root is the same.
func priorDepositKey(config fundingConfig, deposit *depositRecord, slots []depositSlot, ttl uint64) string {
	ordered := append([]depositSlot{}, slots...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].NoteID != ordered[j].NoteID {
			return ordered[i].NoteID < ordered[j].NoteID
		}
		if ordered[i].PreparedAt != ordered[j].PreparedAt {
			return ordered[i].PreparedAt < ordered[j].PreparedAt
		}
		return strings.ToLower(ordered[i].PathSHA256) < strings.ToLower(ordered[j].PathSHA256)
	})
	var key strings.Builder
	fmt.Fprintf(&key, "%s|%s|%d|%d", config.Indexer, strings.ToLower(deposit.Commitment), deposit.Amount, ttl)
	for _, slot := range ordered {
		fmt.Fprintf(&key, "|%d:%d:%s", slot.NoteID, slot.PreparedAt, strings.ToLower(slot.PathSHA256))
	}
	return key.String()
}

// signedDepositSlots lists the slot of every deposit of this note that was
// signed: those kept from earlier attempts and, when a saved deposit
// transaction of this note carries exactly its zero path, the current one.
// A path already kept is not added again, so its earliest preparation stays.
func signedDepositSlots(deposit *depositRecord, record *addressFundingRecord) []depositSlot {
	if deposit == nil {
		return nil
	}
	slots := append([]depositSlot{}, deposit.SignedSlots...)
	current := deposit.Slot
	if current == nil || slices.ContainsFunc(slots, func(slot depositSlot) bool {
		return slot.NoteID == current.NoteID && strings.EqualFold(slot.PathSHA256, current.PathSHA256)
	}) {
		return slots
	}
	for _, entry := range noteDepositTransactions(record, deposit) {
		if _, ok := signedDepositSlot(deposit, &entry); ok {
			return append(slots, *current)
		}
	}
	return slots
}

// noteDepositTransactions returns the saved deposit transactions whose signed
// calldata deposits exactly this note's commitment and amount.
func noteDepositTransactions(record *addressFundingRecord, deposit *depositRecord) []addressTransaction {
	if record == nil || deposit == nil {
		return nil
	}
	var deposits []addressTransaction
	for _, entry := range append(append([]addressTransaction{}, record.History...), pendingAddressTransaction(record.Pending)...) {
		if entry.Kind != "deposit" {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(entry.Raw, "0x"))
		var tx types.Transaction
		if err != nil || tx.UnmarshalBinary(raw) != nil {
			continue
		}
		data := tx.Data()
		if len(data) != 4+34*32 || hex.EncodeToString(data[:4]) != "c588341c" || !strings.EqualFold(hex.EncodeToString(data[4:36]), addressABIWord(deposit.Commitment)) || hex.EncodeToString(data[36:68]) != fmt.Sprintf("%064x", deposit.Amount) {
			continue
		}
		deposits = append(deposits, entry)
	}
	return deposits
}

// findSignedDepositLeaf searches from each signed slot, earliest first. Slots
// with the same note ID are searched once, from the earliest preparation.
func findSignedDepositLeaf(snapshot *treeSnapshot, slots []depositSlot, commitment *big.Int, amount, ttl uint64, now int64) (uint32, bool) {
	ordered := append([]depositSlot{}, slots...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].NoteID != ordered[j].NoteID {
			return ordered[i].NoteID < ordered[j].NoteID
		}
		return ordered[i].PreparedAt < ordered[j].PreparedAt
	})
	for i := range ordered {
		if i > 0 && ordered[i].NoteID == ordered[i-1].NoteID {
			continue
		}
		if id, found := findDepositLeaf(snapshot, &ordered[i], commitment, amount, ttl, now); found {
			return id, true
		}
	}
	return 0, false
}

// findDepositLeaf looks for exactly our leaf (commitment, amount and a
// day-bucketed expiry from plausibleExpiries) at the prepared slot and the
// occupied slots after it. Every comparison costs a Poseidon hash per expiry
// day, so it compares at most depositRevertScanSlots occupied slots. Empty
// slots are skipped without counting. Calldata built for one slot lands at a
// later one only while every slot in between is empty, because the vault
// checks the path against its live root. So when it lands, its slot is the
// first occupied one. Afterwards challengeEscapeWithdrawal can restore leaves
// that escapes removed in between, and a landing behind
// depositRevertScanSlots restored leaves is not found.
func findDepositLeaf(snapshot *treeSnapshot, slot *depositSlot, commitment *big.Int, amount, ttl uint64, now int64) (uint32, bool) {
	expiries := plausibleExpiries(slot.PreparedAt, now, ttl)
	compared := 0
	for id := uint64(slot.NoteID); id < uint64(snapshot.NextNoteID) && compared < depositRevertScanSlots; id++ {
		leaf, ok := parseFieldElement(snapshot.Leaves[id])
		if !ok || leaf.Sign() == 0 {
			continue
		}
		compared++
		for _, expiry := range expiries {
			if leaf.Cmp(noteLeaf(uint32(id), commitment, amount, expiry)) == 0 {
				return uint32(id), true
			}
		}
	}
	return 0, false
}

// plausibleExpiries lists every bucketed expiry for a deposit mined between
// preparation and now, with one day of clock tolerance on each side, limited
// to the depositRevertMaxBuckets days that end one day after now. A deposit
// mined about 63 or more days before the search is not covered. The 30-day
// note TTL of the pinned deployments has passed by then, unless vault pauses
// extended it by more than 33 days.
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
