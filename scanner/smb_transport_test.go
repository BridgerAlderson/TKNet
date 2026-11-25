package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSMBConnectionIdleReceiverAndFreshOperationBudget(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	const timeout = 80 * time.Millisecond
	conn := guardSMBConnection(context.Background(), local, timeout)
	defer conn.Close()
	responses := make(chan error, 3)
	go func() {
		for range 3 {
			var b [1]byte
			_, err := io.ReadFull(conn, b[:])
			responses <- err
			if err != nil {
				return
			}
		}
	}()

	for round := range 3 {
		// The library receiver starts its read before a request is sent. It
		// must survive idle time both before and between actual operations.
		select {
		case err := <-responses:
			t.Fatalf("idle receiver ended in round %d: %v", round, err)
		case <-time.After(2 * timeout):
		}
		err := smbOperationError(conn, func() error {
			// The time spent idle must not eat into this request's budget.
			time.Sleep(timeout / 2)
			if err := peer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				return err
			}
			if _, err := peer.Write([]byte{1}); err != nil {
				return err
			}
			return <-responses
		})
		if err != nil {
			t.Fatalf("fresh operation %d failed: %v", round, err)
		}
	}
}

func TestSMBConnectionProgressExtendsActiveOperation(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	const timeout = 150 * time.Millisecond
	conn := guardSMBConnection(context.Background(), local, timeout)
	defer conn.Close()
	const count = 8
	writerDone := make(chan error, 1)
	go func() {
		for range count {
			time.Sleep(timeout / 3)
			if _, err := peer.Write([]byte{1}); err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()
	start := time.Now()
	n, err := smbOperation(conn, func() (int, error) {
		return io.ReadFull(conn, make([]byte, count))
	})
	if err != nil || n != count {
		t.Fatalf("progressing response was truncated: bytes=%d err=%v", n, err)
	}
	if elapsed := time.Since(start); elapsed <= timeout {
		t.Fatalf("test did not exceed one inactivity interval: %v", elapsed)
	}
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
}

func TestSMBConnectionCancellationStopsIdleReceiver(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := guardSMBConnection(ctx, local, time.Hour)
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled idle read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("scan cancellation left an idle receiver blocked")
	}
}

func TestSMBConnectionWriteBoundedWithoutOperation(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	conn := guardSMBConnection(context.Background(), local, 30*time.Millisecond)
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte{1})
		done <- err
	}()
	select {
	case err := <-done:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("blocked write did not time out: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write outlived its deadline")
	}
}

func TestSMBOperationNestedDeadlineAndCleanup(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			probe := &smbDeadlineProbe{}
			conn := guardSMBConnection(context.Background(), probe, time.Second)
			defer conn.Close()
			sentinel := errors.New("operation failed")
			var got error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil && recovered != sentinel {
						t.Fatalf("unexpected panic: %v", recovered)
					}
				}()
				got = smbOperationError(conn, func() error {
					if probe.deadline().IsZero() {
						t.Fatal("outer operation did not arm the pending read")
					}
					if err := smbOperationError(conn, func() error { return nil }); err != nil {
						return err
					}
					if probe.deadline().IsZero() {
						t.Fatal("nested completion disarmed the outer operation")
					}
					if outcome == "error" {
						return sentinel
					}
					if outcome == "panic" {
						panic(sentinel)
					}
					return nil
				})
			}()
			if outcome == "error" && !errors.Is(got, sentinel) {
				t.Fatalf("operation error changed: %v", got)
			}
			if !probe.deadline().IsZero() {
				t.Fatal("completed operation left the idle read deadline armed")
			}
			if guarded := conn.(*smbConnection); guarded.active != 0 {
				t.Fatalf("operation depth leaked: %d", guarded.active)
			}
		})
	}
}

func TestSMBOperationDeadlineFailureDoesNotRunRequest(t *testing.T) {
	sentinel := errors.New("cannot arm deadline")
	probe := &smbDeadlineProbe{deadlineError: sentinel}
	conn := guardSMBConnection(context.Background(), probe, time.Second)
	defer conn.Close()
	runs := 0
	got, err := smbOperation(conn, func() (int, error) { runs++; return 1, nil })
	if got != 0 || !errors.Is(err, sentinel) || runs != 0 || conn.(*smbConnection).active != 0 {
		t.Fatalf("failed guard ran or leaked operation: value=%d err=%v runs=%d", got, err, runs)
	}
}

func TestSMBConnectionWriteRefreshesBeforeBlocking(t *testing.T) {
	probe := &smbWriteObservation{}
	conn := guardSMBConnection(context.Background(), probe, time.Second)
	defer conn.Close()
	err := smbOperationError(conn, func() error {
		// Model time spent preparing a new request while the receiver is
		// waiting. The response clock must be renewed before socket.Write.
		if err := probe.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			return err
		}
		_, err := conn.Write([]byte{1})
		return err
	})
	if err != nil || !probe.deadlineAtWrite.After(time.Now()) {
		t.Fatalf("request entered Write with a stale response deadline: %v, %v", probe.deadlineAtWrite, err)
	}
}

func TestSMBOperationConcurrentProgressLeavesIdleDeadlineClear(t *testing.T) {
	probe := &smbDeadlineProbe{}
	conn := guardSMBConnection(context.Background(), probe, time.Second)
	defer conn.Close()
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				if err := smbOperationError(conn, func() error {
					if _, err := conn.Read(make([]byte, 1)); err != nil {
						return err
					}
					_, err := conn.Write([]byte{1})
					return err
				}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	workers.Wait()
	if !probe.deadline().IsZero() || conn.(*smbConnection).active != 0 {
		t.Fatal("concurrent progress rearmed an idle receiver or leaked an operation")
	}
}

type smbWriteObservation struct {
	smbDeadlineProbe
	deadlineAtWrite time.Time
}

func (p *smbWriteObservation) Write(b []byte) (int, error) {
	p.deadlineAtWrite = p.deadline()
	return len(b), nil
}

// Records socket deadlines without introducing network timing into the race and
// operation-lifetime checks. Real net.Pipe tests above cover blocking semantics.
type smbDeadlineProbe struct {
	mu            sync.Mutex
	readDeadline  time.Time
	deadlineError error
}

func (p *smbDeadlineProbe) Read(b []byte) (int, error)  { return copy(b, []byte{1}), nil }
func (p *smbDeadlineProbe) Write(b []byte) (int, error) { return len(b), nil }
func (p *smbDeadlineProbe) Close() error                { return nil }
func (p *smbDeadlineProbe) LocalAddr() net.Addr         { return nil }
func (p *smbDeadlineProbe) RemoteAddr() net.Addr        { return nil }
func (p *smbDeadlineProbe) SetDeadline(t time.Time) error {
	return p.SetReadDeadline(t)
}
func (p *smbDeadlineProbe) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deadlineError != nil {
		return p.deadlineError
	}
	p.readDeadline = t
	return nil
}
func (p *smbDeadlineProbe) SetWriteDeadline(time.Time) error { return nil }
func (p *smbDeadlineProbe) deadline() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.readDeadline
}
