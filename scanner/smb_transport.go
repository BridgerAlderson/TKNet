package scanner

import (
	"context"
	"net"
	"sync"
	"time"
)

// go-smb2 keeps a receiver blocked in Read even when no request is outstanding.
// An always-on read deadline would therefore expire healthy, idle sessions.
// Arm inactivity deadlines only while an SMB operation is in progress; scan
// cancellation still closes the socket, including an idle receiver.
type smbConnection struct {
	net.Conn
	timeout time.Duration
	stop    func() bool
	mu      sync.Mutex
	active  int
}

func guardSMBConnection(ctx context.Context, conn net.Conn, timeout time.Duration) net.Conn {
	c := &smbConnection{Conn: conn, timeout: timeout}
	c.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return c
}

func (c *smbConnection) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && err == nil {
		if deadlineErr := c.refreshReadDeadline(); deadlineErr != nil {
			return n, deadlineErr
		}
	}
	return n, err
}

func (c *smbConnection) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	// A request may be assembled while the receiver is already waiting. Give
	// this request a fresh response budget before entering a blocking write.
	if err := c.refreshReadDeadline(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	if n > 0 && err == nil {
		if deadlineErr := c.refreshReadDeadline(); deadlineErr != nil {
			return n, deadlineErr
		}
	}
	return n, err
}

func (c *smbConnection) refreshReadDeadline() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active == 0 {
		return nil
	}
	return c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
}

func (c *smbConnection) beginOperation() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// SetReadDeadline also updates a receiver read that started while idle.
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	c.active++
	return nil
}

func (c *smbConnection) endOperation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active--
	if c.active == 0 {
		_ = c.Conn.SetReadDeadline(time.Time{})
	}
}

// smbOperation bounds inactivity, rather than the whole operation's duration.
// A large response can take several timeout intervals as long as I/O progresses.
func smbOperation[T any](conn net.Conn, operation func() (T, error)) (T, error) {
	if guarded, ok := conn.(*smbConnection); ok {
		if err := guarded.beginOperation(); err != nil {
			var zero T
			return zero, err
		}
		defer guarded.endOperation()
	}
	return operation()
}

func smbOperationError(conn net.Conn, operation func() error) error {
	_, err := smbOperation(conn, func() (struct{}, error) {
		return struct{}{}, operation()
	})
	return err
}

func (c *smbConnection) Close() error {
	c.stop()
	return c.Conn.Close()
}
