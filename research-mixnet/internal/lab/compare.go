// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"sync"
	"time"
)

type CompareConfig struct {
	Clients           int           `json:"clients"`
	Jobs              int           `json:"jobs_per_client"`
	Rate              int           `json:"cells_per_second_per_client_direction"`
	Duration          time.Duration `json:"epoch_duration_ns"`
	MeanDelay         time.Duration `json:"mean_residence_ns"`
	ResponseDelay     time.Duration `json:"max_provider_delay_ns"`
	LossPermille      int           `json:"worker_ingress_loss_permille"`
	DisconnectClients int           `json:"disconnect_clients"`
	Seed              uint64        `json:"public_workload_seed"`
	Cases             []string      `json:"cases"`
}

func DefaultCompareConfig() CompareConfig {
	return CompareConfig{Clients: 16, Jobs: 4, Rate: 2, Duration: 24 * time.Second, MeanDelay: 50 * time.Millisecond,
		ResponseDelay: 750 * time.Millisecond, LossPermille: 20, DisconnectClients: 2, Seed: 20261016, Cases: []string{"clean", "watermark", "loss", "disconnect"}}
}

func (c CompareConfig) validate() error {
	if c.Clients < 2 || c.Clients > 32 || c.Jobs < 2 || c.Jobs > 8 || c.Rate < 1 || c.Rate > 8 || c.Clients*c.Rate > 100 || c.Duration < 3*time.Second || c.Duration > time.Minute ||
		c.MeanDelay < 0 || c.MeanDelay > 250*time.Millisecond || c.ResponseDelay < 0 || c.ResponseDelay > 2*time.Second || c.LossPermille < 0 || c.LossPermille > 100 ||
		c.DisconnectClients < 0 || c.DisconnectClients >= c.Clients || len(c.Cases) < 1 || len(c.Cases) > 4 {
		return errors.New("invalid bounded comparison configuration")
	}
	seen := map[string]bool{}
	for _, scenario := range c.Cases {
		if seen[scenario] {
			return errors.New("duplicate comparison case")
		}
		seen[scenario] = true
		switch scenario {
		case "clean", "watermark", "loss", "disconnect":
		default:
			return errors.New("case must be clean, watermark, loss or disconnect")
		}
	}
	return nil
}

type AttackResult struct {
	Name     string  `json:"name"`
	Samples  int     `json:"samples"`
	Correct  int     `json:"correct"`
	Accuracy float64 `json:"accuracy"`
	Chance   float64 `json:"average_uniform_guess_accuracy"`
}
type TrialReport struct {
	Backend           string       `json:"backend"`
	Scenario          string       `json:"scenario"`
	Status            string       `json:"status"`
	Processes         int          `json:"distinct_peer_processes"`
	Clients           int          `json:"clients"`
	Planned           int          `json:"planned_jobs"`
	Submitted         int          `json:"submitted_jobs"`
	Completed         int          `json:"completed_jobs"`
	CompletionRate    float64      `json:"completed_over_planned"`
	P50MS             float64      `json:"round_trip_p50_ms"`
	P95MS             float64      `json:"round_trip_p95_ms"`
	CellBytes         int          `json:"cell_bytes"`
	Seconds           float64      `json:"epoch_seconds"`
	StreamBytes       uint64       `json:"tcp_stream_bytes_all_links"`
	ClientStreamBytes uint64       `json:"tcp_stream_bytes_client_edges"`
	MiBPerClientHour  float64      `json:"observed_tcp_stream_mib_per_client_hour"`
	BytesPerCompleted *float64     `json:"tcp_stream_bytes_per_completed_job"`
	EventsDropped     uint64       `json:"measurement_events_dropped"`
	LostCells         uint64       `json:"injected_lost_cells"`
	WorkerDrops       uint64       `json:"worker_queue_drops"`
	RejectedCells     uint64       `json:"rejected_cells_all_peers"`
	Disconnected      int          `json:"observed_client_disconnects"`
	Passive           AttackResult `json:"passive_timing_match"`
	Followup          AttackResult `json:"response_release_followup_match"`
	Links             []LinkStats  `json:"links"`
}

type ReferenceStatus struct {
	Backend string `json:"backend"`
	Status  string `json:"status"`
	Version string `json:"version"`
	Reason  string `json:"reason"`
}

func KatzenpostReferenceStatus() ReferenceStatus {
	return ReferenceStatus{Backend: "complete_katzenpost", Status: "not_run_credential_file_policy", Version: "v0.0.107",
		Reason: "The stock Docker generator and server write identity.private.pem and link.private.pem. The user's rule keeps credentials out of files. No keys or testnet were generated; no reference measurements are fabricated."}
}

type ComparisonReport struct {
	Schema            int             `json:"schema"`
	Status            string          `json:"status"`
	Seed              uint64          `json:"public_workload_seed"`
	Configuration     CompareConfig   `json:"configuration"`
	PeerIsolation     string          `json:"peer_isolation"`
	AttackerScope     string          `json:"attacker_scope"`
	MeasurementLimits []string        `json:"measurement_limits"`
	Reference         ReferenceStatus `json:"reference"`
	Trials            []TrialReport   `json:"trials"`
}

type childPeer struct {
	name     string
	cmd      *exec.Cmd
	input    io.WriteCloser
	commands *json.Encoder
	messages chan peerMessage
	done     chan struct{}
	err      error
	info     publicPeer
}

// startChild executes the reviewed binary directly. No shell, key arguments,
// key files, environment credentials or borrowed wallet profiles are used.
func startChild(ctx context.Context, executable string, args []string, name string, record func(peerEvent)) (*childPeer, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "GOTRACEBACK=none"}
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		input.Close()
		return nil, err
	}
	child := &childPeer{name: name, cmd: cmd, input: input, commands: json.NewEncoder(input), messages: make(chan peerMessage, 4), done: make(chan struct{})}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer close(child.messages)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 128*1024)
		for scanner.Scan() {
			var message peerMessage
			if json.Unmarshal(scanner.Bytes(), &message) != nil {
				return
			}
			if message.Type == "event" && message.Event != nil {
				if message.Event.Peer != name {
					return
				}
				record(*message.Event)
				continue
			}
			select {
			case child.messages <- message:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { <-readDone; child.err = cmd.Wait(); close(child.done) }()
	return child, nil
}

func (c *childPeer) wait(ctx context.Context, kind string) (peerMessage, error) {
	select {
	case <-ctx.Done():
		return peerMessage{}, ctx.Err()
	case m, ok := <-c.messages:
		if !ok || m.Type != kind {
			return peerMessage{}, fmt.Errorf("peer %s did not produce %s", c.name, kind)
		}
		return m, nil
	}
}

// Compare runs only synthetic, separate-OS-process experiments. Every source,
// relay and worker owns its private key independently in memory. This is not
// an OS-user, host or independent-operator security boundary.
func Compare(ctx context.Context, cfg CompareConfig, executable string, peerArgs []string, progress io.Writer) (ComparisonReport, error) {
	if err := cfg.validate(); err != nil {
		return ComparisonReport{}, err
	}
	report := ComparisonReport{Schema: 1, Status: "synthetic_process_testbed_only", Seed: cfg.Seed, Configuration: cfg, PeerIsolation: "separate OS address spaces; same user and host; not a sandbox",
		AttackerScope: "Two fixed, untrained timestamp heuristics see only client-edge full-write times and provider receive/release times. Synthetic ground truth is joined only for scoring.",
		Reference:     KatzenpostReferenceStatus(), Trials: []TrialReport{}, MeasurementLimits: []string{
			"Not an anonymity proof or a comprehensive active/global adversary evaluation.", "Single host shares CPU and a wall clock; network geography, independent operators and link authentication are absent.",
			"TCP stream byte counters include HTTP, not TCP/IP headers, retransmissions or physical wire bytes.", "No raw observations, job labels, packet payloads or cryptographic material are persisted.",
			"A missing reply stops that client's sequential workload; there are no automatic retries. Planned, submitted and completed jobs are distinct.",
			"Each scenario changes one factor. The direct control uses the same fixed Sphinx cell geometry but a one-hop request/reply path without cover or mix delays."}}
	for _, scenario := range cfg.Cases {
		for _, mode := range []string{"direct", "prototype"} {
			if ctx.Err() != nil {
				return report, ctx.Err()
			}
			if progress != nil {
				fmt.Fprintf(progress, "running %s/%s with %d clients\n", mode, scenario, cfg.Clients)
			}
			trial, err := runTrial(ctx, cfg, mode, scenario, executable, peerArgs)
			if err != nil {
				return report, fmt.Errorf("%s/%s: %w", mode, scenario, err)
			}
			report.Trials = append(report.Trials, trial)
			if progress != nil {
				fmt.Fprintf(progress, "finished %s/%s: %d/%d jobs; passive %.3f; followup %.3f\n", mode, scenario, trial.Completed, trial.Planned, trial.Passive.Accuracy, trial.Followup.Accuracy)
			}
		}
	}
	return report, nil
}

func runTrial(parent context.Context, cfg CompareConfig, mode, scenario, executable string, peerArgs []string) (TrialReport, error) {
	ctx, cancel := context.WithTimeout(parent, cfg.Duration+30*time.Second)
	defer cancel()
	var children []*childPeer
	defer func() {
		cancel()
		for _, child := range children {
			child.input.Close()
		}
		for _, child := range children {
			<-child.done
		}
	}()
	var mu sync.Mutex
	events := make([]peerEvent, 0, 8192)
	var supervisorDrops uint64
	record := func(event peerEvent) {
		mu.Lock()
		defer mu.Unlock()
		if len(events) >= 100000 {
			supervisorDrops++
			return
		}
		events = append(events, event)
	}
	names := []string{"worker"}
	if mode == "prototype" {
		for i := 0; i < 3; i++ {
			names = append(names, fmt.Sprintf("forward-%d", i), fmt.Sprintf("return-%d", i))
		}
	}
	for i := 0; i < cfg.Clients; i++ {
		names = append(names, fmt.Sprintf("client-%d", i))
	}
	pids := map[int]bool{}
	for _, name := range names {
		child, err := startChild(ctx, executable, peerArgs, name, record)
		if err != nil {
			return TrialReport{}, errors.New("cannot start peer subprocess")
		}
		children = append(children, child)
		message, err := child.wait(ctx, "ready")
		if err != nil {
			return TrialReport{}, err
		}
		if message.Info == nil || message.Info.PID != child.cmd.Process.Pid || pids[message.Info.PID] {
			return TrialReport{}, errors.New("peer process identity mismatch")
		}
		pids[message.Info.PID] = true
		child.info = *message.Info
		child.info.Name = name
	}
	directory := make([]publicPeer, 0, len(children))
	for _, child := range children {
		directory = append(directory, child.info)
	}
	for _, child := range children {
		peerCfg := peerConfig{Name: child.name, Mode: mode, Peers: directory, Clients: cfg.Clients, Rate: cfg.Rate, Jobs: cfg.Jobs, DurationNS: int64(cfg.Duration), Seed: cfg.Seed, MeanDelayNS: int64(cfg.MeanDelay)}
		if scenario == "watermark" {
			peerCfg.ResponseDelayNS = int64(cfg.ResponseDelay)
		}
		if scenario == "loss" {
			peerCfg.LossPermille = cfg.LossPermille
		}
		if scenario == "disconnect" {
			i, err := peerIndex(child.name)
			if err == nil && i < cfg.DisconnectClients {
				peerCfg.DisconnectNS = int64(cfg.Duration / 3)
			}
		}
		if err := child.commands.Encode(peerCommand{Type: "configure", Config: &peerCfg}); err != nil {
			return TrialReport{}, errors.New("peer configuration failed")
		}
		if _, err := child.wait(ctx, "configured"); err != nil {
			return TrialReport{}, err
		}
	}
	start := time.Now().Add(500 * time.Millisecond)
	for _, child := range children {
		if err := child.commands.Encode(peerCommand{Type: "start", StartNS: start.UnixNano()}); err != nil {
			return TrialReport{}, errors.New("peer start failed")
		}
	}
	stats := make([]peerStats, 0, len(children))
	for _, child := range children {
		message, err := child.wait(ctx, "stats")
		if err != nil {
			return TrialReport{}, err
		}
		if message.Stats == nil || message.Stats.Name != child.name {
			return TrialReport{}, errors.New("invalid peer statistics")
		}
		stats = append(stats, *message.Stats)
		child.input.Close()
		select {
		case <-ctx.Done():
			return TrialReport{}, ctx.Err()
		case <-child.done:
			if child.err != nil {
				return TrialReport{}, errors.New("peer exited unsuccessfully")
			}
		}
	}
	mu.Lock()
	observations := append([]peerEvent(nil), events...)
	drops := supervisorDrops
	mu.Unlock()
	trial := analyzeTrial(cfg, mode, scenario, observations, stats)
	trial.Processes = len(pids)
	trial.EventsDropped += drops
	if trial.EventsDropped > 0 {
		trial.Status = "invalid_measurements_dropped"
		trial.Passive = AttackResult{Name: "unavailable"}
		trial.Followup = AttackResult{Name: "unavailable"}
	}
	return trial, nil
}

// Scoring keeps attacker inputs separate from labels. It does not train on the
// evaluated truth or expose a job ID on an observed client-edge cell.
func analyzeTrial(cfg CompareConfig, mode, scenario string, events []peerEvent, stats []peerStats) TrialReport {
	t := TrialReport{Backend: mode, Scenario: scenario, Status: "measured", Clients: cfg.Clients, Planned: cfg.Clients * cfg.Jobs, CellBytes: newCodec().s.Geometry().PacketLength, Seconds: cfg.Duration.Seconds(), Links: []LinkStats{}}
	type truth struct {
		client               string
		submitted, completed int64
		round                int
		followup             bool
	}
	labels := map[string]*truth{}
	guard := map[string][]int64{}
	received := map[string]int64{}
	released := map[string]int64{}
	offline := map[string]int64{}
	for _, e := range events {
		switch e.Kind {
		case "submitted":
			p := labels[e.Job]
			if p == nil {
				p = &truth{}
				labels[e.Job] = p
			}
			p.client = e.Peer
			p.submitted = e.At
			p.round = e.Round
		case "completed":
			p := labels[e.Job]
			if p == nil {
				p = &truth{}
				labels[e.Job] = p
			}
			p.completed = e.At
			p.followup = e.Followup
		case "guard_write":
			if e.Job == "" {
				guard[e.Peer] = append(guard[e.Peer], e.At)
			}
		case "provider_received":
			received[e.Job] = e.At
		case "provider_released":
			released[e.Job] = e.At
		case "disconnected":
			offline[e.Peer] = e.At
		}
	}
	for name := range guard {
		sort.Slice(guard[name], func(i, j int) bool { return guard[name][i] < guard[name][j] })
	}
	latencies := []float64{}
	rounds := map[string]map[int]bool{}
	for _, p := range labels {
		if p.submitted > 0 {
			t.Submitted++
			if rounds[p.client] == nil {
				rounds[p.client] = map[int]bool{}
			}
			rounds[p.client][p.round] = true
		}
		if p.completed >= p.submitted && p.submitted > 0 {
			t.Completed++
			latencies = append(latencies, float64(p.completed-p.submitted)/1e6)
		}
	}
	t.CompletionRate = float64(t.Completed) / float64(t.Planned)
	sort.Float64s(latencies)
	t.P50MS = percentile(latencies, .5)
	t.P95MS = percentile(latencies, .95)
	t.Disconnected = len(offline)
	t.Passive = AttackResult{Name: "nearest_preceding_client_write"}
	t.Followup = AttackResult{Name: "nearest_following_client_write_after_provider_release"}
	for job, at := range received {
		p := labels[job]
		if p == nil || p.submitted == 0 {
			continue
		}
		guess, candidates := nearestClient(guard, offline, at, true, cfg.Clients)
		recordGuess(&t.Passive, guess == p.client, candidates)
	}
	for job, at := range released {
		p := labels[job]
		if p == nil || !p.followup || p.completed == 0 || !rounds[p.client][p.round+1] {
			continue
		}
		guess, candidates := nearestClient(guard, offline, at, false, cfg.Clients)
		recordGuess(&t.Followup, guess == p.client, candidates)
	}
	for _, p := range stats {
		t.EventsDropped += p.EventsDropped
		t.LostCells += p.LostCells
		t.WorkerDrops += p.WorkerDrops
		t.RejectedCells += p.RejectedCells
		for _, l := range p.Links {
			t.Links = append(t.Links, l)
			stream := l.StreamOut + l.StreamIn
			t.StreamBytes += stream
			if len(l.Name) >= 7 && l.Name[:7] == "client-" {
				t.ClientStreamBytes += stream
			} else {
				for i := 0; i < cfg.Clients; i++ {
					suffix := "->" + fmt.Sprintf("client-%d", i)
					if len(l.Name) >= len(suffix) && l.Name[len(l.Name)-len(suffix):] == suffix {
						t.ClientStreamBytes += stream
						break
					}
				}
			}
		}
	}
	t.MiBPerClientHour = float64(t.ClientStreamBytes) * 3600 / (cfg.Duration.Seconds() * float64(cfg.Clients) * 1024 * 1024)
	if t.Completed > 0 {
		n := float64(t.StreamBytes) / float64(t.Completed)
		t.BytesPerCompleted = &n
	}
	return t
}

func percentile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1)*q + .5)
	return sorted[i]
}
func recordGuess(a *AttackResult, correct bool, candidates int) {
	if candidates < 1 {
		return
	}
	a.Samples++
	if correct {
		a.Correct++
	}
	a.Accuracy = float64(a.Correct) / float64(a.Samples)
	a.Chance += (1/float64(candidates) - a.Chance) / float64(a.Samples)
}
func nearestClient(guard map[string][]int64, offline map[string]int64, at int64, before bool, clients int) (string, int) {
	best := ""
	distance := int64(5*time.Second) + 1
	candidates := 0
	for i := 0; i < clients; i++ {
		name := fmt.Sprintf("client-%d", i)
		if t := offline[name]; t > 0 && t <= at {
			continue
		}
		candidates++
		times := guard[name]
		j := sort.Search(len(times), func(i int) bool { return times[i] > at })
		var d int64
		if before {
			if j == 0 {
				continue
			}
			d = at - times[j-1]
		} else {
			if j == len(times) {
				continue
			}
			d = times[j] - at
		}
		if d < distance {
			distance = d
			best = name
		}
	}
	return best, candidates
}

func WriteComparison(out io.Writer, r ComparisonReport) error {
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(r)
}

// Markdown is a concise view of the same aggregate report, with no raw timing
// observations or synthetic job identifiers included.
func ComparisonMarkdown(r ComparisonReport) string {
	var b bytes.Buffer
	fmt.Fprint(&b, "# Headless process comparison\n\nSynthetic single-host measurements; two limited metadata heuristics, not an anonymity proof.\n\n")
	fmt.Fprintln(&b, "| Backend | Case | Completed / planned | p50 / p95 ms | Client MiB/hour | Passive match | Followup match |\n| --- | --- | --- | --- | --- | --- | --- |")
	for _, t := range r.Trials {
		fmt.Fprintf(&b, "| %s | %s | %d / %d | %.0f / %.0f | %.2f | %d/%d (%.1f%%; chance %.1f%%) | %d/%d (%.1f%%; chance %.1f%%) |\n", t.Backend, t.Scenario, t.Completed, t.Planned, t.P50MS, t.P95MS, t.MiBPerClientHour, t.Passive.Correct, t.Passive.Samples, 100*t.Passive.Accuracy, 100*t.Passive.Chance, t.Followup.Correct, t.Followup.Samples, 100*t.Followup.Accuracy, 100*t.Followup.Chance)
	}
	fmt.Fprintf(&b, "\nComplete Katzenpost reference: **%s** (%s). %s\n", r.Reference.Status, r.Reference.Version, r.Reference.Reason)
	fmt.Fprintln(&b, "\nThe direct control uses the same Sphinx cell geometry with one-hop request/reply paths, without cover or mixing. TCP stream bytes include HTTP but exclude TCP/IP headers and retransmission. Percentiles describe completed jobs only. Loss can stop a client's remaining sequential jobs.\n\nPrivacy values summarize fixed nearest-event rules, not a trained or comprehensive attacker. Missing measurements invalidate attack scores. Raw observations and ephemeral keys remain in memory only.")
	return b.String()
}
