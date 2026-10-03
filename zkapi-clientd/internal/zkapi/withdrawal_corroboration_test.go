package zkapi

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestWithdrawalRequiresClearanceOwnershipCapability(t *testing.T) {
	t.Run("shipped manifest keeps the gate inactive", func(t *testing.T) {
		f := newWithdrawalFixture(t)
		f.withdraw(t) // The companion reports no clearance_ownership_proof_version.
		if f.prepareCalls != 1 {
			t.Fatal("an absent capability blocked a legacy deployment's withdrawal")
		}
	})
	for _, capability := range []deploymentCapabilities{{VaultRevision: 2}, {ClearanceOwnershipProof: "required"}, {ClearanceOwnershipProof: "optional"}} {
		t.Run(fmt.Sprintf("%+v", capability), func(t *testing.T) {
			f := newWithdrawalFixture(t)
			f.h.client.capabilities = &capability
			before := f.journal(t)
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err == nil || !strings.Contains(err.Error(), "ownership proofs") {
				t.Fatalf("outdated companion was allowed to reserve the note: %v", err)
			}
			after := f.journal(t)
			if f.prepareCalls != 0 || f.reservedDestination != "" || after.Withdrawal != nil || after.Phase != before.Phase {
				t.Fatal("refused withdrawal reserved the note or saved intent")
			}
			if _, err := f.h.AddressWithdrawal(context.Background()); err != nil {
				t.Fatalf("status reads require the clearance capability: %v", err)
			}
			// A saved withdrawal without a proof plan is gated at prepare.
			f.ownershipProofVersion, f.pending = 1, true
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "waiting_settlement" {
				t.Fatalf("capable companion could not save the withdrawal: %+v %v", status, err)
			}
			f.ownershipProofVersion, f.pending = 0, false
			if _, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err == nil || f.prepareCalls != 0 {
				t.Fatal("a downgraded companion reached prepare for an unplanned withdrawal")
			}
			f.ownershipProofVersion = 1
			hash := f.withdraw(t)
			// Finishing an already signed withdrawal never needs the gate.
			f.ownershipProofVersion = 0
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.prepareCalls != 1 {
				t.Fatalf("the gate blocked finality bookkeeping: %+v %v", status, err)
			}
		})
	}
}

// Review root cause on the withdrawal side: one RPC must not decide that the
// note closed. A forged MutualClose receipt never deletes the companion's
// note state or archives the deposit recovery file.
func TestForgedMutualCloseReceiptNeverClosesNote(t *testing.T) {
	for _, vault := range []string{"forged closed", "honest active"} {
		t.Run(vault, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			hash := f.withdraw(t)
			f.mu.Lock()
			leaf := new(big.Int).Set(f.leaves[12])
			f.mu.Unlock()
			f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
			f.mu.Lock()
			f.setLeaf(12, leaf) // The indexer never saw a close.
			if vault == "honest active" {
				note := f.vaultNotes[12]
				note.status = noteActive
				f.vaultNotes[12] = note
			}
			f.mu.Unlock()
			for range 2 {
				status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
				if err != nil || status.Phase != "withdrawal_pending" || status.Message != withdrawalVerifyingMessage {
					t.Fatalf("forged close was not held pending: %+v %v", status, err)
				}
			}
			if f.confirmCalls != 0 || !f.active || f.journal(t).Pending == nil || f.journal(t).Withdrawal.Phase != "withdrawal_pending" {
				t.Fatal("forged close reached the companion or retired the signed withdrawal")
			}
			if _, err := os.Stat(f.h.statePath); err != nil {
				t.Fatal("forged close archived the deposit recovery file")
			}
			f.mu.Lock()
			f.closeNote(12)
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
			if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
				t.Fatalf("corroborated close did not complete: %+v %v", status, err)
			}
		})
	}
}

// An ownership proof sent for clearance is a valid escape proof. If anyone
// escapes the reserved note with it, the finalized escape of exactly this
// reservation is payout evidence, but only as an independently relayed one.
func TestAddressWithdrawalAcceptsFinalizedEscapeOfSameReservation(t *testing.T) {
	escape := crypto.Keccak256Hash([]byte("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")).Hex()
	for _, destination := range []string{withdrawalTestDestination, addressTestToken} {
		t.Run(destination, func(t *testing.T) {
			f := newWithdrawalFixture(t)
			original := f.withdraw(t)
			f.mineWithdrawal(t, original, withdrawalTestDestination, true)
			if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "reverted" {
				t.Fatalf("revert not reported: %+v %v", status, err)
			}
			other := "0x" + strings.Repeat("c", 64)
			f.mu.Lock()
			logs := []map[string]any{{"address": addressTestVault, "topics": []string{escape, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressABIWord(destination)}}
			f.receipts[other] = map[string]any{"transactionHash": other, "status": "0x1", "blockNumber": "0x10", "blockHash": addressTestBlock, "to": addressTestToken, "logs": logs}
			f.closeNote(12)
			f.mu.Unlock()
			status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID, "", other)
			if destination != withdrawalTestDestination {
				if err == nil || f.confirmCalls != 0 {
					t.Fatal("an escape to another destination was accepted")
				}
				return
			}
			if err != nil || status.Phase != "complete" || f.journal(t).Withdrawal.SettlementHash != other {
				t.Fatalf("finalized escape of the reservation was not accepted: %+v %v", status, err)
			}
			// Our own signed transaction can only be evidenced by MutualClose.
			receipt := &addressReceipt{Status: "0x1", To: addressTestVault}
			raw, _ := json.Marshal(logs)
			_ = json.Unmarshal(raw, &receipt.Logs)
			if err := validateWithdrawalReceipt(receipt, fundingConfig{Contract: addressTestVault}, f.journal(t).Withdrawal, false); err == nil {
				t.Fatal("an escape event was accepted as our own mutual close")
			}
		})
	}
}
