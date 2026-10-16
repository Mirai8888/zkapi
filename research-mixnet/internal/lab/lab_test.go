// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
)

func testNodes(t *testing.T, c *codec, count int) []*node {
	t.Helper()
	nodes := make([]*node, count)
	for i := range nodes {
		pub, priv, err := c.scheme.GenerateKeyPair()
		if err != nil {
			t.Fatal("key generation failed")
		}
		n := &node{public: pub, private: priv}
		if _, err := rand.Read(n.id[:]); err != nil {
			t.Fatal("entropy failed")
		}
		t.Cleanup(priv.Reset)
		nodes[i] = n
	}
	return nodes
}

func TestSphinxFixedSizeAndLayerTransformation(t *testing.T) {
	c := newCodec()
	nodes := testNodes(t, c, 4)
	for _, kind := range []byte{coverKind, requestKind, responseKind} {
		data := []byte("synthetic data")
		if kind == coverKind {
			data = nil
		}
		packet, err := c.packet(nodes, kind, data)
		if err != nil {
			t.Fatal(err)
		}
		for i, n := range nodes {
			before := append([]byte(nil), packet...)
			payload, tag, cmds, err := c.s.Unwrap(n.private, packet)
			if err != nil || len(tag) == 0 {
				t.Fatal("Sphinx unwrap failed")
			}
			if len(packet) != c.s.Geometry().PacketLength {
				t.Fatal("variable cell length")
			}
			if i < len(nodes)-1 {
				if payload != nil || bytes.Equal(before, packet) {
					t.Fatal("relay did not transform opaque cell")
				}
				var next *commands.NextNodeHop
				for _, cmd := range cmds {
					if n, ok := cmd.(*commands.NextNodeHop); ok {
						next = n
					}
				}
				if next == nil || next.ID != nodes[i+1].id {
					t.Fatal("wrong route")
				}
			} else {
				gotKind, got, err := decodeFrame(payload)
				if err != nil || gotKind != kind || !bytes.Equal(data, got) {
					t.Fatal("terminal payload mismatch")
				}
			}
		}
	}
}

func TestSphinxRejectsWrongKeyAndTamperedHeader(t *testing.T) {
	c := newCodec()
	nodes := testNodes(t, c, 4)
	other := testNodes(t, c, 1)[0]
	packet, err := c.packet(nodes, requestKind, []byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.s.Unwrap(other.private, append([]byte(nil), packet...)); err == nil {
		t.Fatal("wrong key accepted")
	}
	packet[0] ^= 1
	if _, _, _, err := c.s.Unwrap(nodes[0].private, packet); err == nil {
		t.Fatal("tampered header accepted")
	}
}

func TestOneUseSURBRoundTripAndKeyErasure(t *testing.T) {
	c := newCodec()
	nodes := testNodes(t, c, 4)
	var id replyID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal("entropy failed")
	}
	surb, keys, err := c.s.NewSURB(rand.Reader, makePath(nodes, &id))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encodeFrame(responseKind, []byte("synthetic reply"))
	if err != nil {
		t.Fatal(err)
	}
	packet, first, err := c.s.NewPacketFromSURB(surb, frame)
	if err != nil || *first != nodes[0].id {
		t.Fatal("SURB routing failed")
	}
	for i, n := range nodes {
		payload, _, cmds, err := c.s.Unwrap(n.private, packet)
		if err != nil {
			t.Fatal(err)
		}
		if len(packet) != c.s.Geometry().PacketLength {
			t.Fatal("reply size differs from forward/cover")
		}
		if i == len(nodes)-1 {
			var found bool
			for _, cmd := range cmds {
				if reply, ok := cmd.(*commands.SURBReply); ok {
					found = reply.ID == id
				}
			}
			if !found {
				t.Fatal("reply label missing")
			}
			plain, err := c.s.DecryptSURBPayload(payload, keys)
			if err != nil || !bytes.Equal(plain, frame) {
				t.Fatal("reply decrypt failed")
			}
			if !bytes.Equal(keys, make([]byte, len(keys))) {
				t.Fatal("SURB keys retained")
			}
		}
	}
}

func TestPoolDelayMixingBoundAndOwnership(t *testing.T) {
	p := newPool(2)
	now := time.Unix(100, 0)
	a := []byte{1}
	if !p.add(a, now.Add(time.Second)) || !p.add([]byte{2}, now) {
		t.Fatal("enqueue failed")
	}
	a[0] = 9
	if p.add([]byte{3}, now) {
		t.Fatal("unbounded pool")
	}
	p.choose = func(int) (int, error) { return 0, nil }
	got, err := p.take(now)
	if err != nil || !bytes.Equal(got, []byte{2}) {
		t.Fatal("residence delay ignored")
	}
	if got, _ := p.take(now); got != nil {
		t.Fatal("released before residence deadline")
	}
	got, err = p.take(now.Add(time.Second))
	if err != nil || !bytes.Equal(got, []byte{1}) {
		t.Fatal("packet ownership was not copied")
	}
	if !p.add([]byte{3}, now) || !p.add([]byte{4}, now) {
		t.Fatal("enqueue failed")
	}
	p.choose = func(n int) (int, error) { return n - 1, nil }
	got, _ = p.take(now)
	if !bytes.Equal(got, []byte{4}) {
		t.Fatal("pool incorrectly forced FIFO")
	}
	p.choose = func(int) (int, error) { return 0, errors.New("synthetic entropy failure") }
	if _, err := p.take(now); err == nil {
		t.Fatal("entropy failure ignored")
	}
}

func TestMissedClockSlotsAreSkippedWithoutCatchUp(t *testing.T) {
	previous := time.Unix(100, 0)
	period := 100 * time.Millisecond
	next, missed := followingSlot(previous, previous.Add(350*time.Millisecond), period)
	if !next.Equal(previous.Add(400*time.Millisecond)) || missed != 3 {
		t.Fatal("overdue slots were not skipped")
	}
	next, missed = followingSlot(previous, previous.Add(50*time.Millisecond), period)
	if !next.Equal(previous.Add(period)) || missed != 0 {
		t.Fatal("original cadence changed")
	}
}

func TestFailedSlotsDoNotRetryOrFollowRedirects(t *testing.T) {
	var targetCalls int
	var mu sync.Mutex
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targetCalls++
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/cell")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	l, err := newLink("redirect", server.URL+"/cell", 20*time.Millisecond, 16, 2, func() ([]byte, error) { return make([]byte, 16), nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	l.run(ctx)
	stats := l.snapshot()
	if stats.Failed < 2 || stats.Failed+stats.Interrupted != stats.Slots || stats.Sent != 0 {
		t.Fatal("failed slots were retried or accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if targetCalls != 0 {
		t.Fatal("redirect followed")
	}
}

func TestLinkNeverAddsTrafficSlotsForQueuedWork(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sizes = append(sizes, int(r.ContentLength))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	cover := func() ([]byte, error) { return bytes.Repeat([]byte{1}, 512), nil }
	l, err := newLink("test", server.URL+"/cell", 20*time.Millisecond, 512, 2, cover)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(2 * time.Second)
	for l.snapshot().Slots < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	before := l.snapshot().Slots
	if !l.enqueue(make([]byte, 512), time.Now()) {
		t.Fatal("enqueue failed")
	}
	deadline = time.Now().Add(2 * time.Second)
	for l.snapshot().Slots < before+5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := l.snapshot()
	if stats.Queued != 1 || stats.Cover < 3 || stats.Cover+stats.Queued != stats.Slots {
		t.Fatal("job did not replace exactly one cover slot")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, size := range sizes {
		if size != 512 {
			t.Fatal("request body size changed")
		}
	}
}

func TestLabTransportRejectsExternalOrAmbiguousEndpoints(t *testing.T) {
	for _, target := range []string{"https://example.org/cell", "http://localhost:1234/cell", "http://127.0.0.1:1234/cell?secret=x", "http://user:synthetic@127.0.0.1:1234/cell", "http://127.0.0.1:1234/other"} {
		if _, err := newLink("test", target, time.Second, 1, 1, func() ([]byte, error) { return []byte{0}, nil }); err == nil {
			t.Fatal("unsafe target accepted")
		}
	}
}

func TestReplayCacheRejectsDuplicatesAndFailsClosedWhenFull(t *testing.T) {
	c := newCodec()
	n, err := newNode(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer n.listener.Close()
	defer n.private.Reset()
	n.replayLimit = 1
	packet, err := c.packet([]*node{n}, coverKind, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), packet...)
	if err := n.accept(packet, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := n.accept(original, time.Now()); err == nil {
		t.Fatal("replay accepted")
	}
	second, err := c.packet([]*node{n}, coverKind, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.accept(second, time.Now()); err == nil {
		t.Fatal("full replay cache silently evicted entries")
	}
}

func TestMalformedFramesAndHTTPCellsAreRejected(t *testing.T) {
	if _, err := encodeFrame(requestKind, make([]byte, payloadBytes)); err == nil {
		t.Fatal("oversize frame accepted")
	}
	frame, _ := encodeFrame(coverKind, nil)
	frame[2] = 255
	if _, _, err := decodeFrame(frame); err == nil {
		t.Fatal("invalid frame length accepted")
	}
	c := newCodec()
	n, err := newNode(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer n.listener.Close()
	defer n.private.Reset()
	req := httptest.NewRequest(http.MethodPost, "http://localhost/cell", bytes.NewReader(make([]byte, 1)))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	n.handle(w, req)
	if w.Code != http.StatusBadRequest || len(n.replay) != 0 {
		t.Fatal("malformed HTTP cell reached Sphinx")
	}
}

func TestIdleCoverFlowsInBothDirectionsWithoutJobs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Duration = 3 * time.Second
	cfg.Rate = 20
	cfg.MeanDelay = 0
	cfg.Jobs = 0
	report, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 0 || report.IdleUploadCover == 0 || report.IdleDownloadCover == 0 {
		t.Fatal("cover depends on jobs")
	}
	for _, link := range report.Links {
		if link.Slots == 0 || link.Sent == 0 || link.Bytes != link.Sent*uint64(report.CellBytes) {
			t.Fatal("link did not carry fixed cells")
		}
		if link.Name == "client-0-upload" && (link.Queued != 0 || link.Cover != link.Slots) {
			t.Fatal("idle source failed to fill every scheduled slot")
		}
	}
}

func TestBidirectionalMixedJobsAcrossClients(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Duration = 4 * time.Second
	cfg.Rate = 20
	cfg.MeanDelay = 10 * time.Millisecond
	cfg.Jobs = 4
	report, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if report.Completed != 4 || report.Submitted != 4 || len(report.LatenciesMS) != 4 {
		t.Fatalf("only %d of 4 synthetic jobs completed", report.Completed)
	}
	if report.EpochSeconds < cfg.Duration.Seconds() {
		t.Fatal("traffic stopped on task completion")
	}
	for _, link := range report.Links {
		if link.Dropped != 0 {
			t.Fatal("unexpected drop in low-load test")
		}
	}
}

func TestCancellationJoinsExperiment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := Run(ctx, DefaultConfig()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("shutdown did not join promptly")
	}
}
