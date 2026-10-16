// SPDX-License-Identifier: AGPL-3.0-or-later
// Package lab runs only a disposable loopback experiment. It has no wallet,
// provider credentials, arbitrary fetcher, persistent keys or public listener.
package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
)

type Config struct {
	Clients   int
	Jobs      int
	Rate      int // Fixed cells/second on each client's upload and download links.
	MeanDelay time.Duration
	Duration  time.Duration
}

func DefaultConfig() Config {
	return Config{Clients: 2, Jobs: 2, Rate: 8, MeanDelay: 50 * time.Millisecond, Duration: 6 * time.Second}
}

func (c Config) validate() error {
	if c.Clients < 1 || c.Clients > 4 || c.Jobs < 0 || c.Jobs > 8 || c.Rate < 1 || c.Rate > 20 ||
		c.MeanDelay < 0 || c.MeanDelay > 250*time.Millisecond || c.Duration < 3*time.Second || c.Duration > 30*time.Second {
		return errors.New("lab requires 1–4 clients, 0–8 jobs, 1–20 cells/s, 0–250ms mean delay and a 3–30s epoch")
	}
	return nil
}

type Report struct {
	Status            string      `json:"status"`
	Crypto            string      `json:"crypto"`
	CellBytes         int         `json:"cell_bytes"`
	EpochSeconds      float64     `json:"epoch_seconds"`
	Clients           int         `json:"clients"`
	Submitted         int         `json:"submitted_jobs"`
	Completed         int         `json:"completed_jobs"`
	LatenciesMS       []int64     `json:"synthetic_round_trip_ms"`
	IdleUploadCover   uint64      `json:"upload_cover_cells_before_jobs"`
	IdleDownloadCover uint64      `json:"download_cover_cells_before_jobs"`
	ClientMiBPerHour  float64     `json:"scheduled_bidirectional_cell_mib_per_client_hour"`
	Links             []LinkStats `json:"links"`
}

type pendingReply struct {
	keys    []byte
	started time.Time
}
type client struct {
	node      *node
	source    *link
	download  *link
	mu        sync.Mutex
	pending   map[replyID]pendingReply
	latencies []int64
}

func (c *client) receive(cell terminalCell) {
	for _, cmd := range cell.commands {
		if reply, ok := cmd.(*commands.SURBReply); ok {
			c.mu.Lock()
			pending, exists := c.pending[reply.ID]
			delete(c.pending, reply.ID)
			c.mu.Unlock()
			if !exists {
				return
			}
			plain, err := c.node.codec.s.DecryptSURBPayload(cell.payload, pending.keys)
			if err != nil {
				return
			}
			kind, data, err := decodeFrame(plain)
			if err != nil || kind != responseKind || !bytes.Equal(data, []byte("synthetic research result")) {
				return
			}
			c.mu.Lock()
			c.latencies = append(c.latencies, time.Since(pending.started).Milliseconds())
			c.mu.Unlock()
			return
		}
	}
	// Forward cover packets terminate here without consuming SURB keys.
}

type researchRequest struct {
	Text  string `json:"text"`
	Reply []byte `json:"reply"` // Opaque one-use Sphinx route, never a callback URL.
}

func (c *client) submit(code *codec, forward, reverse []*node, text string) error {
	var id replyID
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	path := append(append([]*node(nil), reverse...), c.node)
	surb, keys, err := code.s.NewSURB(rand.Reader, makePath(path, &id))
	if err != nil {
		return err
	}
	raw, err := json.Marshal(researchRequest{Text: text, Reply: surb})
	if err != nil {
		return err
	}
	packet, err := code.packet(forward, requestKind, raw)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.pending[id] = pendingReply{keys: keys, started: time.Now()}
	c.mu.Unlock()
	if !c.source.enqueue(packet, time.Now()) {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		for i := range keys {
			keys[i] = 0
		}
		return errors.New("client queue full")
	}
	return nil
}

// Run exercises real HTTP loopback links and unmodified Sphinx/SURB operations.
// Completion does not stop cover. Only the fixed epoch or cancellation stops it.
func Run(parent context.Context, cfg Config) (Report, error) {
	if err := cfg.validate(); err != nil {
		return Report{}, err
	}
	code := newCodec()
	ctx, cancel := context.WithCancel(parent)
	var nodes []*node
	var links []*link
	var clients []*client
	var wg sync.WaitGroup
	defer func() {
		cancel()
		for _, n := range nodes {
			n.close()
		}
		wg.Wait()
		for _, c := range clients {
			if c == nil {
				continue
			}
			c.mu.Lock()
			for _, pending := range c.pending {
				for i := range pending.keys {
					pending.keys[i] = 0
				}
			}
			c.mu.Unlock()
		}
		for _, n := range nodes {
			n.private.Reset()
		}
	}()
	addNode := func() (*node, error) {
		n, err := newNode(code, cfg.MeanDelay)
		if err == nil {
			nodes = append(nodes, n)
		}
		return n, err
	}
	forward, reverse := make([]*node, 4), make([]*node, 3)
	for i := range forward {
		n, err := addNode()
		if err != nil {
			return Report{}, err
		}
		forward[i] = n
	}
	for i := range reverse {
		n, err := addNode()
		if err != nil {
			return Report{}, err
		}
		reverse[i] = n
	}
	clients = make([]*client, cfg.Clients)
	for i := range clients {
		n, err := addNode()
		if err != nil {
			return Report{}, err
		}
		clients[i] = &client{node: n, pending: make(map[replyID]pendingReply)}
		n.onTerminal = clients[i].receive
	}
	clientPeriod := time.Second / time.Duration(cfg.Rate)
	sharedPeriod := time.Second / time.Duration(cfg.Rate*cfg.Clients)
	addLink := func(name string, from, to *node, period time.Duration, cover func() ([]byte, error)) (*link, error) {
		l, err := newLink(name, to.endpoint(), period, code.s.Geometry().PacketLength, 64, cover)
		if err != nil {
			return nil, err
		}
		links = append(links, l)
		if from != nil {
			from.routes[to.id] = l
		}
		return l, nil
	}
	for i, c := range clients {
		l, err := addLink(fmt.Sprintf("client-%d-upload", i), nil, forward[0], clientPeriod, code.cover(forward))
		if err != nil {
			return Report{}, err
		}
		c.source = l
	}
	for i := 0; i < 3; i++ {
		_, err := addLink(fmt.Sprintf("forward-%d", i+1), forward[i], forward[i+1], sharedPeriod, code.cover(forward[i+1:]))
		if err != nil {
			return Report{}, err
		}
	}
	randomReturnCover := func(path []*node) func() ([]byte, error) {
		return func() ([]byte, error) {
			i, err := randomIndex(len(clients))
			if err != nil {
				return nil, err
			}
			nodes := append(append([]*node(nil), path...), clients[i].node)
			return code.packet(nodes, coverKind, nil)
		}
	}
	exit := forward[3]
	workerOut, err := addLink("worker-return", exit, reverse[0], sharedPeriod, randomReturnCover(reverse))
	if err != nil {
		return Report{}, err
	}
	for i := 0; i < 2; i++ {
		_, err := addLink(fmt.Sprintf("reverse-%d", i+1), reverse[i], reverse[i+1], sharedPeriod, randomReturnCover(reverse[i+1:]))
		if err != nil {
			return Report{}, err
		}
	}
	for i, c := range clients {
		l, err := addLink(fmt.Sprintf("client-%d-download", i), reverse[2], c.node, clientPeriod, code.cover([]*node{c.node}))
		if err != nil {
			return Report{}, err
		}
		c.download = l
	}
	exit.onTerminal = func(cell terminalCell) {
		kind, raw, err := decodeFrame(cell.payload)
		if err != nil || kind != requestKind {
			return
		}
		var job researchRequest
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&job) != nil || d.Decode(new(any)) != io.EOF || len(job.Text) > 1024 || len(job.Text) == 0 || len(job.Reply) != code.s.Geometry().SURBLength {
			return
		}
		// Synthetic worker only. No external inference, search, payments or tools.
		frame, err := encodeFrame(responseKind, []byte("synthetic research result"))
		if err != nil {
			return
		}
		packet, first, err := code.s.NewPacketFromSURB(job.Reply, frame)
		if err != nil || *first != reverse[0].id {
			return
		}
		workerOut.enqueue(packet, time.Now())
	}
	for _, n := range nodes {
		n.start(ctx, &wg)
	}
	for _, l := range links {
		wg.Add(1)
		go func(l *link) { defer wg.Done(); l.run(ctx) }(l)
	}
	started := time.Now()
	// Epoch duration is fixed before traffic starts, not chosen by job completion.
	idle := time.NewTimer(cfg.Duration / 4)
	defer idle.Stop()
	end := time.NewTimer(cfg.Duration)
	defer end.Stop()
	report := Report{Status: "loopback_experiment_only", Crypto: "Katzenpost Sphinx v0.0.107; X25519 classical", CellBytes: code.s.Geometry().PacketLength,
		Clients: cfg.Clients, LatenciesMS: []int64{}, Links: []LinkStats{}, ClientMiBPerHour: 2 * float64(code.s.Geometry().PacketLength*cfg.Rate) * 3600 / (1024 * 1024)}
	select {
	case <-parent.Done():
		return Report{}, parent.Err()
	case <-idle.C:
	}
	for _, c := range clients {
		report.IdleUploadCover += c.source.snapshot().Cover
		report.IdleDownloadCover += c.download.snapshot().Cover
	}
	for i := 0; i < cfg.Jobs; i++ {
		if err := clients[i%len(clients)].submit(code, forward, reverse, "Find primary sources about mixnet research transport."); err != nil {
			return Report{}, err
		}
		report.Submitted++
	}
	select {
	case <-parent.Done():
		return Report{}, parent.Err()
	case <-end.C:
	}
	cancel()
	for _, n := range nodes {
		n.close()
	}
	wg.Wait()
	report.EpochSeconds = time.Since(started).Seconds()
	for _, c := range clients {
		c.mu.Lock()
		report.Completed += len(c.latencies)
		report.LatenciesMS = append(report.LatenciesMS, c.latencies...)
		for _, pending := range c.pending {
			for i := range pending.keys {
				pending.keys[i] = 0
			}
		}
		c.mu.Unlock()
	}
	for _, l := range links {
		report.Links = append(report.Links, l.snapshot())
	}
	return report, nil
}
