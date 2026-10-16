// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
)

// Only public directory data crosses the supervisor pipe. Every private key is
// generated inside its owning process; no key file or secret argument exists.
type publicPeer struct {
	Name     string `json:"name"`
	ID       nodeID `json:"id"`
	Public   []byte `json:"public"`
	Endpoint string `json:"endpoint"`
	PID      int    `json:"pid"`
}

type peerConfig struct {
	Name            string       `json:"name"`
	Mode            string       `json:"mode"`
	Peers           []publicPeer `json:"peers"`
	Clients         int          `json:"clients"`
	Rate            int          `json:"rate"`
	Jobs            int          `json:"jobs"`
	DurationNS      int64        `json:"duration_ns"`
	MeanDelayNS     int64        `json:"mean_delay_ns"`
	ResponseDelayNS int64        `json:"response_delay_ns"`
	LossPermille    int          `json:"loss_permille"`
	Seed            uint64       `json:"seed"` // Public workload/fault seed; never used for crypto.
	DisconnectNS    int64        `json:"disconnect_ns"`
}

type peerCommand struct {
	Type    string      `json:"type"`
	Config  *peerConfig `json:"config,omitempty"`
	StartNS int64       `json:"start_ns,omitempty"`
}
type peerEvent struct {
	Kind     string `json:"kind"`
	Peer     string `json:"peer"`
	Job      string `json:"job,omitempty"` // Synthetic random label, never a crypto key.
	At       int64  `json:"at"`
	Round    int    `json:"round,omitempty"`
	Followup bool   `json:"followup,omitempty"`
}
type peerStats struct {
	Name          string      `json:"name"`
	Links         []LinkStats `json:"links"`
	EventsDropped uint64      `json:"events_dropped"`
	LostCells     uint64      `json:"injected_lost_cells"`
	WorkerDrops   uint64      `json:"worker_queue_drops"`
	RejectedCells uint64      `json:"rejected_cells"`
}
type peerMessage struct {
	Type  string      `json:"type"`
	Info  *publicPeer `json:"info,omitempty"`
	Event *peerEvent  `json:"event,omitempty"`
	Stats *peerStats  `json:"stats,omitempty"`
}

type processRequest struct {
	Job   string `json:"job"`
	Reply []byte `json:"reply"`
}
type processPending struct {
	job   string
	keys  []byte
	round int
}

func readCommand(scanner *bufio.Scanner) (peerCommand, error) {
	if !scanner.Scan() {
		return peerCommand{}, errors.New("peer control channel closed")
	}
	var command peerCommand
	d := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&command) != nil || d.Decode(new(any)) != io.EOF {
		return command, errors.New("invalid peer control message")
	}
	return command, nil
}

func peerIndex(name string) (int, error) {
	if !strings.HasPrefix(name, "client-") {
		return 0, errors.New("invalid client name")
	}
	return strconv.Atoi(strings.TrimPrefix(name, "client-"))
}

// RunPeer is an internal subprocess protocol. Stdout carries public bootstrap
// data and synthetic experiment observations to its parent, never private keys.
func RunPeer(parent context.Context, in io.Reader, out io.Writer) error {
	code := newCodec()
	n, err := newNode(code, 0)
	if err != nil {
		return errors.New("cannot initialize peer")
	}
	defer n.private.Reset()
	defer n.listener.Close()
	encoder := json.NewEncoder(out)
	info := publicPeer{ID: n.id, Public: n.public.Bytes(), Endpoint: n.endpoint(), PID: os.Getpid()}
	if err := encoder.Encode(peerMessage{Type: "ready", Info: &info}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	command, err := readCommand(scanner)
	if err != nil {
		return err
	}
	if command.Type != "configure" || command.Config == nil {
		return errors.New("configuration required")
	}
	cfg := *command.Config
	if cfg.Mode != "direct" && cfg.Mode != "prototype" {
		return errors.New("unknown peer backend")
	}
	if cfg.Clients < 1 || cfg.Clients > 32 || cfg.Jobs < 1 || cfg.Jobs > 8 || cfg.Rate < 1 || cfg.Rate > 8 || cfg.Rate*cfg.Clients > 100 ||
		cfg.DurationNS < int64(3*time.Second) || cfg.DurationNS > int64(time.Minute) || cfg.MeanDelayNS < 0 || cfg.MeanDelayNS > int64(250*time.Millisecond) ||
		cfg.ResponseDelayNS < 0 || cfg.ResponseDelayNS > int64(2*time.Second) || cfg.LossPermille < 0 || cfg.LossPermille > 100 || cfg.DisconnectNS < 0 || cfg.DisconnectNS > cfg.DurationNS {
		return errors.New("invalid bounded peer configuration")
	}
	peers := make(map[string]*node)
	endpoints := make(map[string]string)
	for _, p := range cfg.Peers {
		if _, exists := peers[p.Name]; exists {
			return errors.New("duplicate peer")
		}
		public, err := code.scheme.UnmarshalBinaryPublicKey(p.Public)
		if err != nil {
			return errors.New("invalid public directory")
		}
		peers[p.Name] = &node{id: p.ID, public: public}
		endpoints[p.Name] = p.Endpoint
	}
	self := peers[cfg.Name]
	if self == nil || self.id != n.id {
		return errors.New("peer directory mismatch")
	}
	isClient := strings.HasPrefix(cfg.Name, "client-")
	index := -1
	if isClient {
		index, err = peerIndex(cfg.Name)
		if err != nil || index < 0 || index >= cfg.Clients {
			return errors.New("invalid client")
		}
	}
	var forward, reverse []*node
	if cfg.Mode == "prototype" {
		for i := 0; i < 3; i++ {
			forward = append(forward, peers[fmt.Sprintf("forward-%d", i)])
			reverse = append(reverse, peers[fmt.Sprintf("return-%d", i)])
		}
	}
	forward = append(forward, peers["worker"])
	for _, p := range append(append([]*node(nil), forward...), reverse...) {
		if p == nil {
			return errors.New("incomplete public directory")
		}
	}
	for i := 0; i < cfg.Clients; i++ {
		if peers[fmt.Sprintf("client-%d", i)] == nil {
			return errors.New("incomplete client directory")
		}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var wg sync.WaitGroup
	var dropped, lost, workerDrops atomic.Uint64
	events := make(chan peerEvent, 4096)
	var eventMu sync.RWMutex
	eventsClosed := false
	emitEvent := func(e peerEvent) {
		eventMu.RLock()
		defer eventMu.RUnlock()
		if eventsClosed {
			return
		}
		select {
		case events <- e:
		default:
			dropped.Add(1)
		}
	}
	emit := func(kind, job string, round int, followup bool) {
		emitEvent(peerEvent{Kind: kind, Peer: cfg.Name, Job: job, At: time.Now().UnixNano(), Round: round, Followup: followup})
	}
	var links []*link
	clientPeriod := time.Second / time.Duration(cfg.Rate)
	sharedPeriod := time.Second / time.Duration(cfg.Rate*cfg.Clients)
	addLink := func(target string, path []*node, period time.Duration, randomClient bool) (*link, error) {
		cover := func() ([]byte, error) {
			p := append([]*node(nil), path...)
			if randomClient {
				i, err := randomIndex(cfg.Clients)
				if err != nil {
					return nil, err
				}
				p = append(p, peers[fmt.Sprintf("client-%d", i)])
			}
			return code.packet(p, coverKind, nil)
		}
		to := peers[target]
		if to == nil {
			return nil, errors.New("missing next hop")
		}
		l, err := newLink(cfg.Name+"->"+target, endpoints[target], period, code.s.Geometry().PacketLength, 256, cover)
		if err != nil {
			return nil, err
		}
		l.uncovered = cfg.Mode == "direct"
		if isClient {
			l.onWrite = func(at time.Time) {
				emitEvent(peerEvent{Kind: "guard_write", Peer: cfg.Name, At: at.UnixNano()})
			}
		}
		links = append(links, l)
		n.routes[to.id] = l
		return l, nil
	}
	var source *link
	switch {
	case isClient:
		target := "worker"
		if cfg.Mode == "prototype" {
			target = "forward-0"
		}
		source, err = addLink(target, forward, clientPeriod, false)
	case cfg.Name == "worker":
		if cfg.Mode == "prototype" {
			_, err = addLink("return-0", reverse, sharedPeriod, true)
		} else {
			for i := 0; i < cfg.Clients && err == nil; i++ {
				name := fmt.Sprintf("client-%d", i)
				_, err = addLink(name, []*node{peers[name]}, clientPeriod, false)
			}
		}
	case strings.HasPrefix(cfg.Name, "forward-"):
		i, e := strconv.Atoi(strings.TrimPrefix(cfg.Name, "forward-"))
		if e != nil || i < 0 || i > 2 {
			return errors.New("unknown relay")
		}
		target := "worker"
		if i < 2 {
			target = fmt.Sprintf("forward-%d", i+1)
		}
		_, err = addLink(target, forward[i+1:], sharedPeriod, false)
		n.mean = time.Duration(cfg.MeanDelayNS)
	case strings.HasPrefix(cfg.Name, "return-"):
		i, e := strconv.Atoi(strings.TrimPrefix(cfg.Name, "return-"))
		if e != nil || i < 0 || i > 2 {
			return errors.New("unknown relay")
		}
		if i < 2 {
			_, err = addLink(fmt.Sprintf("return-%d", i+1), reverse[i+1:], sharedPeriod, true)
		} else {
			for j := 0; j < cfg.Clients && err == nil; j++ {
				name := fmt.Sprintf("client-%d", j)
				_, err = addLink(name, []*node{peers[name]}, clientPeriod, false)
			}
		}
		n.mean = time.Duration(cfg.MeanDelayNS)
	default:
		return errors.New("unknown role")
	}
	if err != nil {
		return err
	}
	if cfg.Name == "worker" && cfg.LossPermille > 0 {
		rng := mathrand.New(mathrand.NewPCG(cfg.Seed, 73))
		var mu sync.Mutex
		n.beforeCell = func() bool {
			mu.Lock()
			drop := rng.IntN(1000) < cfg.LossPermille
			mu.Unlock()
			if drop {
				lost.Add(1)
			}
			return drop
		}
	}
	pending := make(map[replyID]processPending)
	var pendingMu sync.Mutex
	completed := make(chan int, 8)
	if isClient {
		n.onTerminal = func(cell terminalCell) {
			for _, command := range cell.commands {
				r, ok := command.(*commands.SURBReply)
				if !ok {
					continue
				}
				pendingMu.Lock()
				p, exists := pending[r.ID]
				delete(pending, r.ID)
				pendingMu.Unlock()
				if !exists {
					return
				}
				plain, err := code.s.DecryptSURBPayload(cell.payload, p.keys)
				if err != nil {
					return
				}
				kind, data, err := decodeFrame(plain)
				if err != nil || kind != responseKind || string(data) != p.job {
					return
				}
				emit("completed", p.job, p.round, p.round+1 < cfg.Jobs)
				select {
				case completed <- p.round:
				default:
					dropped.Add(1)
				}
				return
			}
		}
	} else if cfg.Name == "worker" {
		capacity := make(chan struct{}, 32)
		n.onTerminal = func(cell terminalCell) {
			kind, raw, err := decodeFrame(cell.payload)
			if err != nil || kind != requestKind {
				return
			}
			var request processRequest
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || len(request.Job) != 32 || len(request.Reply) != code.s.Geometry().SURBLength {
				return
			}
			if _, err := hex.DecodeString(request.Job); err != nil {
				return
			}
			emit("provider_received", request.Job, 0, false)
			select {
			case capacity <- struct{}{}:
			default:
				workerDrops.Add(1)
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-capacity }()
				delay := time.Duration(0)
				if cfg.ResponseDelayNS > 0 {
					h := sha256.Sum256([]byte(request.Job))
					delay = time.Duration(int64(h[0]%3) * cfg.ResponseDelayNS / 2)
				}
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
				frame, err := encodeFrame(responseKind, []byte(request.Job))
				if err != nil {
					return
				}
				packet, first, err := code.s.NewPacketFromSURB(request.Reply, frame)
				if err != nil {
					return
				}
				l := n.routes[*first]
				if l == nil {
					return
				}
				emit("provider_released", request.Job, 0, false)
				l.enqueue(packet, time.Now())
			}()
		}
	}
	if err := encoder.Encode(peerMessage{Type: "configured"}); err != nil {
		return err
	}
	start, err := readCommand(scanner)
	if err != nil {
		return err
	}
	if start.Type != "start" || start.StartNS <= time.Now().UnixNano() {
		return errors.New("future epoch required")
	}
	begin := time.Unix(0, start.StartNS)
	duration := time.Duration(cfg.DurationNS)
	if isClient && cfg.DisconnectNS > 0 && cfg.DisconnectNS < cfg.DurationNS {
		duration = time.Duration(cfg.DisconnectNS)
	}
	end := begin.Add(duration)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for event := range events {
			e := event
			if encoder.Encode(peerMessage{Type: "event", Event: &e}) != nil {
				cancel()
				return
			}
		}
	}()
	var finishOnce sync.Once
	finish := func() {
		finishOnce.Do(func() {
			cancel()
			n.close()
			wg.Wait()
			pendingMu.Lock()
			for _, p := range pending {
				for i := range p.keys {
					p.keys[i] = 0
				}
			}
			pendingMu.Unlock()
			eventMu.Lock()
			eventsClosed = true
			close(events)
			eventMu.Unlock()
			<-writerDone
		})
	}
	defer finish()
	n.start(ctx, &wg)
	for _, l := range links {
		// Public seed affects only a preselected clock phase, not packet entropy.
		h := sha256.Sum256([]byte(l.name))
		phase := time.Duration(int64(h[0]) * int64(l.period) / 256)
		l.startAt = begin.Add(l.period + phase)
		wg.Add(1)
		go func(l *link) { defer wg.Done(); l.run(ctx) }(l)
	}
	if isClient {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := mathrand.New(mathrand.NewPCG(cfg.Seed, uint64(index+1)))
			initial := 500*time.Millisecond + time.Duration(rng.Int64N(int64(2*time.Second)))
			timer := time.NewTimer(time.Until(begin.Add(initial)))
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			for round := 0; round < cfg.Jobs; round++ {
				var nonce [16]byte
				var id replyID
				if _, err := rand.Read(nonce[:]); err != nil {
					return
				}
				if _, err := rand.Read(id[:]); err != nil {
					return
				}
				job := hex.EncodeToString(nonce[:])
				path := append(append([]*node(nil), reverse...), n)
				surb, keys, err := code.s.NewSURB(rand.Reader, makePath(path, &id))
				if err != nil {
					return
				}
				raw, err := json.Marshal(processRequest{Job: job, Reply: surb})
				if err != nil {
					return
				}
				packet, err := code.packet(forward, requestKind, raw)
				if err != nil {
					for i := range keys {
						keys[i] = 0
					}
					return
				}
				pendingMu.Lock()
				pending[id] = processPending{job: job, keys: keys, round: round}
				pendingMu.Unlock()
				emit("submitted", job, round, round+1 < cfg.Jobs)
				if !source.enqueue(packet, time.Now()) {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-completed:
				}
				if round+1 < cfg.Jobs {
					think := time.NewTimer(20 * time.Millisecond)
					select {
					case <-ctx.Done():
						think.Stop()
						return
					case <-think.C:
					}
				}
			}
		}()
	}
	// EOF cancels the child if its supervisor dies. Only "stop" is accepted.
	go func() { _, _ = readCommand(scanner); cancel() }()
	epoch := time.NewTimer(time.Until(end))
	defer epoch.Stop()
	select {
	case <-ctx.Done():
	case <-epoch.C:
	}
	if isClient && duration < time.Duration(cfg.DurationNS) {
		emit("disconnected", "", 0, false)
	}
	finish()
	stats := peerStats{Name: cfg.Name, EventsDropped: dropped.Load(), LostCells: lost.Load(), WorkerDrops: workerDrops.Load(), RejectedCells: n.rejected.Load(), Links: []LinkStats{}}
	for _, l := range links {
		stats.Links = append(stats.Links, l.snapshot())
	}
	return encoder.Encode(peerMessage{Type: "stats", Stats: &stats})
}
