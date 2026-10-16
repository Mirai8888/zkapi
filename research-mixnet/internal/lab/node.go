// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
)

type terminalCell struct {
	payload  []byte
	commands []commands.RoutingCommand
}
type node struct {
	id          nodeID
	public      nike.PublicKey
	private     nike.PrivateKey
	codec       *codec
	mean        time.Duration
	routes      map[nodeID]*link // Immutable after startup; packets cannot select arbitrary URLs.
	listener    net.Listener
	server      *http.Server
	mu          sync.Mutex
	replay      map[string]struct{}
	replayLimit int
	terminal    chan terminalCell
	onTerminal  func(terminalCell)
	rejected    atomic.Uint64
}

func newNode(c *codec, mean time.Duration) (*node, error) {
	public, private, err := c.scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	n := &node{public: public, private: private, codec: c, mean: mean, routes: make(map[nodeID]*link),
		replay: make(map[string]struct{}), replayLimit: 16384, terminal: make(chan terminalCell, 32)}
	if _, err := rand.Read(n.id[:]); err != nil {
		private.Reset()
		return nil, err
	}
	n.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		private.Reset()
		return nil, err
	}
	n.server = &http.Server{Handler: http.HandlerFunc(n.handle), ReadHeaderTimeout: time.Second, ReadTimeout: time.Second,
		WriteTimeout: time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
	return n, nil
}

func (n *node) endpoint() string { return "http://" + n.listener.Addr().String() + "/cell" }

func (n *node) accept(packet []byte, now time.Time) error {
	if len(packet) != n.codec.s.Geometry().PacketLength {
		return errors.New("invalid cell")
	}
	payload, tag, cmds, err := n.codec.s.Unwrap(n.private, packet)
	if err != nil {
		return errors.New("invalid cell")
	}
	n.mu.Lock()
	_, duplicate := n.replay[string(tag)]
	// No eviction under a live key: filling the replay cache fails closed.
	if duplicate || len(n.replay) >= n.replayLimit {
		n.mu.Unlock()
		return errors.New("replayed cell or epoch full")
	}
	n.replay[string(tag)] = struct{}{}
	n.mu.Unlock()
	for _, cmd := range cmds {
		if next, ok := cmd.(*commands.NextNodeHop); ok {
			out := n.routes[next.ID]
			if out == nil {
				return errors.New("unknown next hop")
			}
			delay, err := residence(n.mean)
			if err != nil {
				return err
			}
			if !out.enqueue(packet, now.Add(delay)) {
				return errors.New("mix pool full")
			}
			return nil
		}
	}
	if payload == nil {
		return errors.New("no terminal payload")
	}
	select {
	case n.terminal <- terminalCell{payload: payload, commands: cmds}:
		return nil
	default:
		return errors.New("terminal pool full")
	}
}

func (n *node) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.Path != "/cell" || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" ||
		r.ContentLength != int64(n.codec.s.Geometry().PacketLength) || r.Header.Get("Content-Type") != "application/octet-stream" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(n.codec.s.Geometry().PacketLength))
	packet, err := io.ReadAll(r.Body)
	if err != nil || n.accept(packet, time.Now()) != nil {
		n.rejected.Add(1)
	}
	// No distinction between valid, replayed, full and invalid Sphinx cells.
	w.WriteHeader(http.StatusAccepted)
}

func (n *node) start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(2)
	go func() { defer wg.Done(); _ = n.server.Serve(n.listener) }()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case cell := <-n.terminal:
				if ctx.Err() != nil {
					return
				}
				if n.onTerminal != nil {
					n.onTerminal(cell)
				}
			}
		}
	}()
}
