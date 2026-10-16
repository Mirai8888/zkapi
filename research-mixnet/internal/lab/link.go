// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
)

type LinkStats struct {
	Name        string `json:"name"`
	Slots       uint64 `json:"scheduled_slots"`
	Queued      uint64 `json:"queued_cells"`
	Cover       uint64 `json:"locally_generated_cover_cells"`
	Sent        uint64 `json:"successful_cells"`
	Failed      uint64 `json:"failed_slots"`
	Interrupted uint64 `json:"cancellation_interrupted_slots"`
	Missed      uint64 `json:"missed_clock_slots"`
	Dropped     uint64 `json:"queue_drops"`
	Bytes       uint64 `json:"successful_cell_bytes"`
	StreamOut   uint64 `json:"tcp_stream_bytes_written"`
	StreamIn    uint64 `json:"tcp_stream_bytes_read"`
	Pending     int    `json:"queued_cells_at_end"`
}

type link struct {
	name, target string
	period       time.Duration
	cellBytes    int
	queue        *pool
	cover        func() ([]byte, error)
	mu           sync.Mutex
	stats        LinkStats
	uncovered    bool
	startAt      time.Time
	notice       chan struct{}
	onWrite      func(time.Time)
}

func newLink(name, target string, period time.Duration, size, capacity int, cover func() ([]byte, error)) (*link, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "/cell" || u.RawQuery != "" || u.Fragment != "" || u.Port() == "" {
		return nil, errors.New("lab transport requires a literal loopback cell endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || period < 10*time.Millisecond || size < 1 || capacity < 1 || cover == nil {
		return nil, errors.New("invalid lab link")
	}
	return &link{name: name, target: target, period: period, cellBytes: size, queue: newPool(capacity), cover: cover, stats: LinkStats{Name: name}, notice: make(chan struct{}, 1)}, nil
}

func (l *link) enqueue(packet []byte, ready time.Time) bool {
	if len(packet) == l.cellBytes && l.queue.add(packet, ready) {
		select {
		case l.notice <- struct{}{}:
		default:
		}
		return true
	}
	l.mu.Lock()
	l.stats.Dropped++
	l.mu.Unlock()
	return false
}

func (l *link) snapshot() LinkStats {
	l.mu.Lock()
	stats := l.stats
	l.mu.Unlock()
	l.queue.mu.Lock()
	stats.Pending = len(l.queue.cells)
	l.queue.mu.Unlock()
	return stats
}

func (l *link) next(now time.Time) ([]byte, bool, error) {
	packet, err := l.queue.take(now)
	if err != nil {
		return nil, false, err
	}
	if packet != nil {
		return packet, false, nil
	}
	packet, err = l.cover()
	return packet, true, err
}

func (l *link) run(ctx context.Context) {
	dialer := &net.Dialer{Timeout: l.period / 2}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &countedConn{Conn: conn, link: l}, nil
		}, ResponseHeaderTimeout: l.period / 2}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: l.period / 2,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	scheduled := l.startAt
	if scheduled.IsZero() {
		scheduled = time.Now().Add(l.period)
	}
	if l.uncovered {
		l.runUncovered(ctx, client)
		return
	}
	timer := time.NewTimer(time.Until(scheduled))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if ctx.Err() != nil {
				return
			}
			// Deadlines stay on the original clock, never on job arrival times.
			packet, cover, err := l.next(time.Now())
			l.mu.Lock()
			l.stats.Slots++
			if cover {
				l.stats.Cover++
			} else if packet != nil {
				l.stats.Queued++
			}
			l.mu.Unlock()
			if err == nil {
				err = l.send(ctx, client, packet)
			}
			l.mu.Lock()
			if err != nil && ctx.Err() != nil {
				// Delivery may already have occurred; never retry an ambiguous slot.
				l.stats.Interrupted++
			} else if err != nil {
				l.stats.Failed++
			} else {
				l.stats.Sent++
				l.stats.Bytes += uint64(len(packet))
			}
			l.mu.Unlock()
			var missed uint64
			scheduled, missed = followingSlot(scheduled, time.Now(), l.period)
			l.mu.Lock()
			l.stats.Missed += missed
			l.mu.Unlock()
			timer.Reset(time.Until(scheduled))
		}
	}
}

type countedConn struct {
	net.Conn
	link *link
}

func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.link.mu.Lock()
	c.link.stats.StreamOut += uint64(n)
	c.link.mu.Unlock()
	return n, err
}
func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.link.mu.Lock()
	c.link.stats.StreamIn += uint64(n)
	c.link.mu.Unlock()
	return n, err
}

func (l *link) send(ctx context.Context, client *http.Client, packet []byte) error {
	if len(packet) != l.cellBytes {
		return errors.New("invalid cell size")
	}
	if l.onWrite != nil {
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				l.onWrite(time.Now())
			}
		}})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.target, bytes.NewReader(packet))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "research-mixnet-lab/0.1")
	response, err := client.Do(req)
	if response != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		response.Body.Close()
		if response.StatusCode != http.StatusAccepted {
			err = errors.New("cell not accepted")
		}
	}
	return err
}

// An uncovered control retains the same Sphinx geometry and HTTP transport.
// Only traffic scheduling and the path differ from the covered experiment.
func (l *link) runUncovered(ctx context.Context, client *http.Client) {
	if !l.startAt.IsZero() {
		timer := time.NewTimer(time.Until(l.startAt))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.notice:
			for {
				packet, err := l.queue.take(time.Now())
				if err != nil || packet == nil {
					break
				}
				err = l.send(ctx, client, packet)
				l.mu.Lock()
				l.stats.Slots++
				l.stats.Queued++
				if err != nil && ctx.Err() != nil {
					l.stats.Interrupted++
				} else if err != nil {
					l.stats.Failed++
				} else {
					l.stats.Sent++
					l.stats.Bytes += uint64(len(packet))
				}
				l.mu.Unlock()
			}
		}
	}
}

// Skip expired slots instead of draining a stale ticker and sending a burst.
func followingSlot(previous, now time.Time, period time.Duration) (time.Time, uint64) {
	next := previous.Add(period)
	if next.After(now) {
		return next, 0
	}
	missed := uint64(now.Sub(next)/period) + 1
	return next.Add(time.Duration(missed) * period), missed
}
