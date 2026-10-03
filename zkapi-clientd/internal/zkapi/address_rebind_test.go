package zkapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// Review regressions 2 and 4: an RPC that reports a wrong note ID is refused,
// and once the chain view is honest, rebind binds the note secret to the
// note the finalized vault and the indexer agree on.
func TestWrongNoteIDReceiptIsRefusedAndRebindRecoversCorrectNote(t *testing.T) {
	f, hash := minedNativeDeposit(t)
	f.mu.Lock()
	expiry := f.vaultNotes[12].expiry
	f.receipts[hash]["logs"] = depositEventReceipt(addressTestVault, 0xA4A4, "0x1234", 100000, expiry).Logs
	f.vaultNotes[0xA4A4] = f.vaultNotes[12] // The hostile RPC also forges notes().
	f.mu.Unlock()
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "verification_conflict" || f.activated != 0 {
		t.Fatalf("wrong note ID was not refused: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil {
		t.Fatal("a conflicting deposit allowed a fresh deposit quote")
	}
	f.mu.Lock()
	f.receipts[hash]["logs"] = depositEventReceipt(addressTestVault, 12, "0x1234", 100000, expiry).Logs
	delete(f.vaultNotes, 0xA4A4)
	f.finalized = "0x20"
	f.mu.Unlock()
	status, err = f.h.RebindDeposit(context.Background(), nil, nil)
	if err != nil || status.Phase != "active" || f.activated != 1 || f.resetCalls != 0 {
		t.Fatalf("rebind did not activate the verified note: %+v %v", status, err)
	}
	body := f.confirmBodies[0]
	if body["note_id"] != float64(12) || body["expiry_ts"] != float64(expiry) || body["amount"] != float64(100000) || body["secret"] != "0xabcdef" {
		t.Fatalf("companion bound to the wrong note: %+v", body)
	}
	record := f.savedDeposit(t)
	if !record.Active || record.Binding == nil || record.Binding.NoteID != 12 || record.Binding.ExpiryTs != expiry || record.Rebind != nil || record.Secret != "0xabcdef" || record.Commitment != "0x1234" || record.TransactionHash != hash {
		t.Fatalf("rebind changed note material or lost the binding: %+v", record)
	}
	if address := f.savedAddress(t); address.Phase != "active" || address.Pending == nil || address.Pending.Hash != hash {
		t.Fatalf("the verified deposit transaction was not kept: %+v", address)
	}
	if again, err := f.h.FundAddress(context.Background(), 100000); err != nil || again.Phase != "active" || f.activated != 1 || len(f.accepted) != 1 {
		t.Fatalf("rebound note was activated twice or replaced: %+v %v", again, err)
	}
}

// activatedWithWrongCompanionNote is a pre-fix wallet: the deposit is note 12
// on chain, but the companion was initialized at the RPC's note 0xA4A4.
func activatedWithWrongCompanionNote(t *testing.T) (*addressFixture, uint64) {
	t.Helper()
	f, _ := minedNativeDeposit(t)
	if status, err := f.h.FundAddress(context.Background(), 100000); err != nil || status.Phase != "active" {
		t.Fatalf("fixture did not activate: %+v %v", status, err)
	}
	f.finalized = "0x20"
	record := f.savedDeposit(t)
	record.Binding = nil // Older releases kept no binding.
	if err := f.h.save(record); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	expiry := f.vaultNotes[12].expiry
	f.walletNote = map[string]any{"note_id": 0xA4A4, "deposit_amount": 100000, "current_balance": 100000, "expiry_ts": expiry, "is_genesis": true}
	f.activated, f.confirmBodies = 0, nil
	return f, expiry
}

func TestRebindReplacesOnlyNamedGenesisCompanionNote(t *testing.T) {
	f, expiry := activatedWithWrongCompanionNote(t)
	wrong, other := uint64(0xA4A4), uint64(7)
	for name, refusal := range map[string]struct {
		replace *uint64
		mutate  func()
		restore func()
	}{
		"unnamed":       {nil, func() {}, func() {}},
		"wrong id":      {&other, func() {}, func() {}},
		"not genesis":   {&wrong, func() { f.walletNote["is_genesis"] = false }, func() { f.walletNote["is_genesis"] = true }},
		"spent balance": {&wrong, func() { f.walletNote["current_balance"] = 99999 }, func() { f.walletNote["current_balance"] = 100000 }},
		"other amount": {&wrong, func() { f.walletNote["deposit_amount"], f.walletNote["current_balance"] = 99999, 99999 }, func() {
			f.walletNote["deposit_amount"], f.walletNote["current_balance"] = 100000, 100000
		}},
		"pending request": {&wrong, func() { f.walletPending = true }, func() { f.walletPending = false }},
		"reserved withdrawal": {&wrong, func() {
			f.withdrawalPhase = map[string]any{"phase": "reserved", "note_id": 0xA4A4, "destination": withdrawalTestDestination, "final_balance": "100000", "withdrawal_nullifier": "0x123"}
		}, func() { f.withdrawalPhase = nil }},
	} {
		f.mu.Lock()
		refusal.mutate()
		f.mu.Unlock()
		_, err := f.h.RebindDeposit(context.Background(), nil, refusal.replace)
		f.mu.Lock()
		refusal.restore()
		f.mu.Unlock()
		if err == nil {
			t.Fatalf("%s: rebind replaced the companion note", name)
		}
		if name == "unnamed" && !strings.Contains(err.Error(), "--replace-note-id 42148") {
			t.Fatalf("unnamed replacement did not explain the flag: %v", err)
		}
		if f.resetCalls != 0 || f.activated != 0 || f.savedDeposit(t).Rebind != nil {
			t.Fatalf("%s: refused rebind reset, confirmed, or journaled a replacement", name)
		}
	}
	status, err := f.h.RebindDeposit(context.Background(), nil, &wrong)
	if err != nil || status.Phase != "active" || f.resetCalls != 1 || f.activated != 1 {
		t.Fatalf("named genesis note was not replaced exactly once: %+v %v", status, err)
	}
	if body := f.confirmBodies[0]; body["note_id"] != float64(12) || body["expiry_ts"] != float64(expiry) {
		t.Fatalf("replacement used the wrong binding: %+v", body)
	}
	if record := f.savedDeposit(t); record.Rebind != nil || record.Binding == nil || record.Binding.NoteID != 12 || !record.Active {
		t.Fatalf("replacement was not committed: %+v", record)
	}
}

func TestRebindResumesAfterCrashBetweenResetAndConfirm(t *testing.T) {
	for _, failing := range []string{"/funding/api/deposit/confirm", "/wallet/reset"} {
		t.Run(failing, func(t *testing.T) {
			f, expiry := activatedWithWrongCompanionNote(t)
			upstream := f.h.client.local.Transport
			f.h.client.local.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == failing {
					return withdrawalJSONResponse(r, 503, map[string]any{"error": "interrupted"}), nil
				}
				return upstream.RoundTrip(r)
			})
			wrong := uint64(0xA4A4)
			if _, err := f.h.RebindDeposit(context.Background(), nil, &wrong); err == nil {
				t.Fatal("interrupted rebind reported success")
			}
			journal := f.savedDeposit(t).Rebind
			if journal == nil || journal.FromNoteID != 0xA4A4 || journal.ToNoteID != 12 || journal.ExpiryTs != expiry {
				t.Fatalf("replacement was not journaled before reset: %+v", journal)
			}
			f.h.client.local.Transport = upstream
			// The resumed rebind needs no flags and replays nothing extra.
			status, err := f.h.RebindDeposit(context.Background(), nil, nil)
			if err != nil || status.Phase != "active" || f.activated != 1 || f.resetCalls != 1 {
				t.Fatalf("interrupted rebind did not resume once: %+v %v (reset %d)", status, err, f.resetCalls)
			}
			if record := f.savedDeposit(t); record.Rebind != nil || record.Binding == nil || record.Binding.NoteID != 12 {
				t.Fatalf("resumed rebind was not committed: %+v", record)
			}
			other := uint64(13)
			if _, err := f.h.RebindDeposit(context.Background(), &other, nil); err == nil {
				t.Fatal("a completed rebind accepted an unverified note")
			}
		})
	}
}

// Without a usable receipt, only our exact leaf near the slot the signed
// calldata targeted identifies the note; anything else needs --note-id.
func TestRebindAutoSelectsOnlyOurLeafNearPreparedSlot(t *testing.T) {
	for _, landed := range []string{"foreign", "next slot"} {
		t.Run(landed, func(t *testing.T) {
			f := newAddressFixture(t, true)
			first, err := f.fundNative(t, 100000)
			if err != nil {
				t.Fatal(err)
			}
			f.mine(t, first.TransactionHash, true) // The RPC reports a revert.
			f.mu.Lock()
			f.registerDeposit(12, "0x1234", 1, bucketedExpiry()) // A foreign 1 gwei copy.
			if landed == "next slot" {
				// Identical siblings after a close let the calldata land one slot later.
				f.registerDeposit(13, "0x1234", 100000, bucketedExpiry())
			}
			f.mu.Unlock()
			status, err := f.h.RebindDeposit(context.Background(), nil, nil)
			if landed == "foreign" {
				if err == nil || !strings.Contains(err.Error(), "--note-id") || f.activated != 0 {
					t.Fatalf("a foreign deposit was adopted: %+v %v", status, err)
				}
				note := uint64(12)
				if _, err := f.h.RebindDeposit(context.Background(), &note, nil); err == nil || f.activated != 0 {
					t.Fatal("an explicit foreign 1 gwei note was adopted")
				}
				return
			}
			if err != nil || status.Phase != "active" || f.confirmBodies[0]["note_id"] != float64(13) {
				t.Fatalf("our leaf after the prepared slot was not recovered: %+v %v", status, err)
			}
		})
	}
}
