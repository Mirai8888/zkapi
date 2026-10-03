package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestFundRebindFlagsAreExclusiveAndValidated(t *testing.T) {
	c := config.Config{Backend: "zkapi", Listen: "127.0.0.1:1"}
	for _, args := range [][]string{
		{"--rebind", "--resume"},
		{"--rebind", "--amount", "1"},
		{"--rebind", "--usd", "5"},
		{"--rebind", "--approve", testQuoteID},
		{"--note-id", "12"},
		{"--replace-note-id", "12"},
		{"--resume", "--note-id", "12"},
		{"--rebind", "--note-id", ""},
		{"--rebind", "--note-id", "-1"},
		{"--rebind", "--note-id", "+12"},
		{"--rebind", "--note-id", "0x0c"},
		{"--rebind", "--note-id", "4294967296"},
		{"--rebind", "--replace-note-id", "1e3"},
		{"--rebind", "extra"},
	} {
		if err := runFunding(context.Background(), c, args, &bytes.Buffer{}); err == nil || strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("invalid rebind options reached the daemon: %v: %v", args, err)
		}
	}
	for value, want := range map[string]uint64{"0": 0, "12": 12, "4294967295": 4294967295, "0042148": 42148} {
		if got, err := parseNoteID(value); err != nil || got != want {
			t.Fatalf("%s: got %d, %v", value, got, err)
		}
	}
}

func TestFundRebindPostsExplicitNoteIDs(t *testing.T) {
	for _, scenario := range []struct {
		args  []string
		body  map[string]uint64
		phase string
	}{
		{[]string{"--rebind"}, map[string]uint64{}, "active"},
		{[]string{"--rebind", "--note-id", "12"}, map[string]uint64{"note_id": 12}, "active"},
		{[]string{"--rebind", "--note-id", "12", "--replace-note-id", "42148"}, map[string]uint64{"note_id": 12, "replace_note_id": 42148}, "active"},
		{[]string{"--rebind", "--replace-note-id", "42148"}, map[string]uint64{"replace_note_id": 42148}, "verification_conflict"},
	} {
		t.Run(strings.Join(scenario.args, " "), func(t *testing.T) {
			var posts []map[string]uint64
			s := fundingCLITestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/admin/funding/address":
					_ = json.NewEncoder(w).Encode(fundingTestStatus("verification_conflict"))
				case r.Method == http.MethodPost && r.URL.Path == "/admin/funding/rebind":
					var body map[string]uint64
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Error("invalid rebind body")
					}
					posts = append(posts, body)
					state := fundingTestStatus(scenario.phase)
					state["message"] = "Rebind status from the daemon."
					_ = json.NewEncoder(w).Encode(state)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
			}))
			defer s.Close()
			var out bytes.Buffer
			err := runFunding(context.Background(), fundingTestConfig(s), scenario.args, &out)
			if (scenario.phase == "active") != (err == nil) {
				t.Fatalf("rebind result %v for phase %s", err, scenario.phase)
			}
			if len(posts) != 1 || len(posts[0]) != len(scenario.body) {
				t.Fatalf("rebind posted %v, want %v", posts, scenario.body)
			}
			for key, value := range scenario.body {
				if posts[0][key] != value {
					t.Fatalf("rebind posted %v, want %v", posts[0], scenario.body)
				}
			}
			if !strings.Contains(out.String(), scenario.phase+": Rebind status from the daemon.") {
				t.Fatalf("rebind progress was not printed: %s", out.String())
			}
		})
	}
}

func TestGuidedFundingShowsVerifyingStageAndStopsOnConflict(t *testing.T) {
	f := newWizardFixture()
	f.address = func() zkapi.AddressFundingStatus { return wizardState("confirming") }
	f.resume = func(uint64) (zkapi.AddressFundingStatus, error) {
		if f.resumeCalls == 1 {
			state := wizardState("confirming")
			state.DepositStage = "verifying"
			return state, nil
		}
		return wizardState("verification_conflict"), nil
	}
	f.ready = func(int) zkapi.WalletReadiness { return zkapi.WalletReadiness{} }
	ui := &fundingWizardUI{}
	err := guidedFunding(context.Background(), f, "", ui, immediateWizardPoll)
	if err == nil || !strings.Contains(err.Error(), "deposit needs attention") {
		t.Fatalf("verification conflict did not stop guided funding: %v", err)
	}
	if !strings.Contains(ui.String(), "waiting for the zkAPI indexer to confirm it before activation") {
		t.Fatalf("verifying stage was not shown: %s", ui.String())
	}
	if f.resumeCalls != 2 || f.approveCalls != 0 || f.quoteCalls != 0 {
		t.Fatal("guided funding retried, requoted, or approved during verification")
	}
}
