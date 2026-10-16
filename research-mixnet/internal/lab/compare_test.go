// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProcessPeerHelper(t *testing.T) {
	for _, arg := range os.Args {
		if arg == "research-peer-helper" {
			if RunPeer(context.Background(), os.Stdin, os.Stdout) != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
	}
}

func processTestArgs() []string {
	return []string{"-test.run=^TestProcessPeerHelper$", "--", "research-peer-helper"}
}

func TestTimingScorerCannotUseGroundTruth(t *testing.T) {
	cfg := DefaultCompareConfig()
	cfg.Clients = 2
	events := []peerEvent{
		{Kind: "submitted", Peer: "client-0", Job: "synthetic-label-a", At: 50},
		{Kind: "guard_write", Peer: "client-0", At: 100},
		{Kind: "guard_write", Peer: "client-1", At: 199},
		{Kind: "provider_received", Peer: "worker", Job: "synthetic-label-a", At: 200},
		{Kind: "provider_released", Peer: "worker", Job: "synthetic-label-a", At: 300},
		{Kind: "completed", Peer: "client-0", Job: "synthetic-label-a", At: 320, Followup: true},
		{Kind: "guard_write", Peer: "client-1", At: 350},
		{Kind: "submitted", Peer: "client-0", Job: "synthetic-label-b", At: 380, Round: 1},
		{Kind: "guard_write", Peer: "client-0", At: 400},
	}
	report := analyzeTrial(cfg, "prototype", "clean", events, nil)
	for _, attack := range []AttackResult{report.Passive, report.Followup} {
		if attack.Samples != 1 || attack.Correct != 0 || attack.Accuracy != 0 || attack.Chance != .5 {
			t.Fatalf("attacker must guess using observed times, not truth: %+v", attack)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil || strings.Contains(string(raw), "synthetic-label") {
		t.Fatal("aggregate report exposed synthetic job labels")
	}
}

func TestDisconnectCandidatesUseQueryTime(t *testing.T) {
	guard := map[string][]int64{"client-0": {100, 400}, "client-1": {199, 350}}
	offline := map[string]int64{"client-1": 250}
	guess, n := nearestClient(guard, offline, 300, false, 2)
	if guess != "client-0" || n != 1 {
		t.Fatalf("disconnected peer remained a candidate: %q %d", guess, n)
	}
	guess, n = nearestClient(guard, offline, 200, true, 2)
	if guess != "client-1" || n != 2 {
		t.Fatalf("future disconnect leaked into past scoring: %q %d", guess, n)
	}
}

func TestEmptyComparisonDoesNotInventMeasurements(t *testing.T) {
	r := analyzeTrial(DefaultCompareConfig(), "prototype", "clean", nil, nil)
	if r.Completed != 0 || r.BytesPerCompleted != nil || r.P50MS != 0 || r.P95MS != 0 || r.Passive.Samples != 0 || r.Followup.Samples != 0 {
		t.Fatalf("invented measurements: %+v", r)
	}
}

func TestComparisonRejectsInvalidConfigBeforeLaunch(t *testing.T) {
	for _, cfg := range []CompareConfig{
		{Clients: 1000},
		func() CompareConfig { c := DefaultCompareConfig(); c.Cases = []string{"katzenpost"}; return c }(),
	} {
		if _, err := Compare(context.Background(), cfg, "/does-not-exist", nil, nil); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestChildCancellationReapsProcess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	child, err := startChild(ctx, executable, processTestArgs(), "worker", func(peerEvent) {})
	if err != nil {
		t.Fatal(err)
	}
	defer child.input.Close()
	if _, err := child.wait(ctx, "ready"); err != nil {
		t.Fatal(err)
	}
	if child.cmd.Dir != "/" || len(child.cmd.Env) != 3 {
		t.Fatal("child inherited workspace or parent environment")
	}
	cancel()
	select {
	case <-child.done:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled child was not reaped")
	}
}

func TestSeparateProcessComparison(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultCompareConfig()
	cfg.Clients, cfg.Jobs, cfg.Rate = 2, 2, 8
	cfg.Duration, cfg.MeanDelay = 8*time.Second, 0
	cfg.DisconnectClients, cfg.Cases = 1, []string{"clean"}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	report, err := Compare(ctx, cfg, executable, processTestArgs(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Trials) != 2 {
		t.Fatalf("wanted two actual trials: %+v", report)
	}
	for i, r := range report.Trials {
		wantProcesses := 3
		if i == 1 {
			wantProcesses += 6
		}
		if r.Processes != wantProcesses || r.Completed < 1 || r.Completed > 4 || r.Submitted < 2 || r.EventsDropped != 0 || r.StreamBytes == 0 || r.Passive.Samples < 1 || r.Followup.Samples > 2 {
			t.Fatalf("incomplete process experiment: %+v", r)
		}
		if i == 0 && (r.Completed != 4 || r.Passive.Samples != 4 || r.Followup.Samples != 2) {
			t.Fatalf("direct control did not finish its bounded workload: %+v", r)
		}
	}
	if report.Reference.Status != "not_run_credential_file_policy" {
		t.Fatal("reference status misrepresented")
	}
}

func TestCanceledComparisonDoesNotLaunch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Compare(ctx, DefaultCompareConfig(), "/does-not-exist", nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wanted cancellation, got %v", err)
	}
}

func TestNodeCloseJoinsInflightHandler(t *testing.T) {
	n, err := newNode(newCodec(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer n.private.Reset()
	defer n.close()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	n.beforeCell = func() bool { close(entered); <-release; return true }
	request := httptest.NewRequest(http.MethodPost, "/cell", bytes.NewReader(make([]byte, n.codec.s.Geometry().PacketLength)))
	request.Header.Set("Content-Type", "application/octet-stream")
	go func() { n.handle(httptest.NewRecorder(), request); close(done) }()
	<-entered
	closed := make(chan struct{})
	go func() { n.close(); close(closed) }()
	select {
	case <-closed:
		close(release)
		t.Fatal("close returned before a handler using the private key finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not join completed handler")
	}
	<-done
	// A late handler must not touch the hook or erased key after close returns.
	n.handle(httptest.NewRecorder(), request)
}
