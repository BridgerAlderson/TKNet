package scanner

import (
	"context"
	"errors"
	"hash/fnv"
	"net"
	"syscall"
	"time"
)

const smbConnectAttempts = 3

// Retry only the initial TCP connection: no SMB negotiation or credentials have
// been sent at this point. Never wrap CheckSMB/authenticate in this retry loop.
func connectSMB(ctx context.Context, target string, timeout time.Duration, attempts int, dial func(context.Context, string, time.Duration) (net.Conn, error), wait func(context.Context, time.Duration) error) (net.Conn, []string, error) {
	var failures []string
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, failures, err
		}
		var conn net.Conn
		conn, err = dial(ctx, target, timeout)
		if err == nil {
			return conn, failures, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		failures = append(failures, smbConnectFailure(err))
		if ctx.Err() != nil || !retrySMBConnect(err) || attempt+1 == attempts {
			break
		}
		// Spread retries across hosts instead of repeating a burst together.
		hash := fnv.New32a()
		_, _ = hash.Write([]byte(target))
		delay := time.Duration(200*(attempt+1)+int(hash.Sum32()%200)) * time.Millisecond
		if err := wait(ctx, delay); err != nil {
			return nil, failures, err
		}
	}
	return nil, failures, err
}

func waitSMBConnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retrySMBConnect(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var network net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ETIMEDOUT) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENOBUFS)
}

func smbConnectFailure(err error) string {
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "route or host unreachable"
	case errors.Is(err, syscall.ENOBUFS), errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		return "local resource exhaustion"
	default:
		return "connection failed"
	}
}
