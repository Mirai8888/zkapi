// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

type queuedCell struct {
	packet []byte
	ready  time.Time
}

// Each outgoing link has a bounded pool, sampled without preserving FIFO order.
// A packet replaces a cover slot; it never adds a slot or accelerates the clock.
type pool struct {
	mu       sync.Mutex
	cells    []queuedCell
	capacity int
	choose   func(int) (int, error)
}

func newPool(capacity int) *pool { return &pool{capacity: capacity, choose: randomIndex} }

func (p *pool) add(packet []byte, ready time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cells) >= p.capacity {
		return false
	}
	p.cells = append(p.cells, queuedCell{packet: append([]byte(nil), packet...), ready: ready})
	return true
}

func (p *pool) take(now time.Time) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	eligible := make([]int, 0, len(p.cells))
	for i, cell := range p.cells {
		if !now.Before(cell.ready) {
			eligible = append(eligible, i)
		}
	}
	if len(eligible) == 0 {
		return nil, nil
	}
	selected, err := p.choose(len(eligible))
	if err != nil {
		return nil, err
	}
	i := eligible[selected]
	packet := p.cells[i].packet
	p.cells[i] = p.cells[len(p.cells)-1]
	p.cells[len(p.cells)-1] = queuedCell{}
	p.cells = p.cells[:len(p.cells)-1]
	return packet, nil
}

// Capped exponential residence time is a lab parameter, not a Loopix proof.
func residence(mean time.Duration) (time.Duration, error) {
	if mean == 0 {
		return 0, nil
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	u := float64((binary.BigEndian.Uint64(b[:])>>11)+1) / float64((uint64(1)<<53)+1)
	d := -math.Log(u) * float64(mean)
	if d > float64(8*mean) {
		d = float64(8 * mean)
	}
	return time.Duration(d), nil
}
