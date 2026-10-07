package zkapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realVaultLayout is the revision-3 vault's selectors and event layouts as
// the compiled protocol/contracts sources produce them
// (crates/zkapi-serverd/tests/fixtures/vault_calldata_golden.json, which
// check-calldata-golden.sh keeps equal to the contracts).
type realVaultLayout struct {
	Selectors map[string]string `json:"selectors"`
	Events    map[string]struct {
		Topic0 string `json:"topic0"`
		Topics string `json:"topics"`
		Data   string `json:"data"`
	} `json:"events"`
}

func loadRealVaultLayout(t *testing.T) realVaultLayout {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "crates", "zkapi-serverd", "tests", "fixtures", "vault_calldata_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var layout realVaultLayout
	if err := json.Unmarshal(raw, &layout); err != nil {
		t.Fatal(err)
	}
	return layout
}

func TestEverySelectorAndTopicIsTheRealVaults(t *testing.T) {
	layout := loadRealVaultLayout(t)
	selectors := map[string]string{
		"mutualClose":               withdrawalSelector,
		"initiateEscapeWithdrawal":  escapeSelector,
		"finalizeEscapeWithdrawal":  finalizeEscapeSelector,
		"claimEscapePayout":         claimEscapePayoutSelector,
		"escapePayoutCredits":       escapePayoutCreditsSelector,
		"notes":                     notesSelector,
		"proofAdapter":              selectorProofAdapter,
		"stateSigningKeyX":          selectorStateSigningKeyX,
		"stateSigningKeyY":          selectorStateSigningKeyY,
		"clearanceSigningKeyX":      selectorClearanceSigningKeyX,
		"clearanceSigningKeyY":      selectorClearanceSigningKeyY,
		"challengePeriod":           selectorChallengePeriod,
		"noteTtl":                   selectorNoteTTL,
		"maxPauseDuration":          selectorMaxPauseDuration,
		"CONCESSION_ESCAPE_VERSION": selectorConcessionEscapeVersion,
		"ROOT_HISTORY_WINDOW":       selectorRootHistoryWindow,
		"CIRCUIT_ID_HASH":           selectorCircuitIDHash,
		"REQUEST_VK_HASH":           selectorRequestVKHash,
		"WITHDRAWAL_VK_HASH":        selectorWithdrawalVKHash,
		"deposit":                   "c588341c",
	}
	for name, ours := range selectors {
		real, ok := layout.Selectors[name]
		if !ok {
			t.Fatalf("the real vault layout has no %s", name)
		}
		if "0x"+strings.TrimPrefix(ours, "0x") != real {
			t.Fatalf("%s: clientd uses %s, the real vault %s", name, ours, real)
		}
	}
	topics := map[string]string{
		"MutualClose":               withdrawalEventTopic,
		"EscapeWithdrawalFinalized": escapeFinalizedEventTopic,
		"EscapePayoutDeferred":      escapePayoutDeferredEventTopic,
		"EscapeConcessionRecorded":  escapeConcessionRecordedTopic,
		"EscapeConcessionRaised":    escapeConcessionRaisedTopic,
		"NoteDeposited":             depositEventTopic,
	}
	for name, ours := range topics {
		event, ok := layout.Events[name]
		if !ok {
			t.Fatalf("the real vault layout has no event %s", name)
		}
		if !strings.EqualFold(ours, event.Topic0) {
			t.Fatalf("%s: clientd matches topic %s, the real vault emits %s", name, ours, event.Topic0)
		}
	}
	// The payout matchers read EscapeWithdrawalFinalized as two topics and
	// three data words, and EscapePayoutDeferred as three topics and one word.
	if finalized := layout.Events["EscapeWithdrawalFinalized"]; len(finalized.Topics) != 2+2*64 || !isHex(finalized.Data, 96) {
		t.Fatalf("EscapeWithdrawalFinalized layout changed: %+v", finalized)
	}
	if deferred := layout.Events["EscapePayoutDeferred"]; len(deferred.Topics) != 2+3*64 || !isHex(deferred.Data, 32) {
		t.Fatalf("EscapePayoutDeferred layout changed: %+v", deferred)
	}
}
