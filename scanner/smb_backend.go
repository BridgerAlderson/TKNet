package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// This narrow boundary lets regression tests count authentication separately
// from share authorization, without a network, real credentials or a domain.
// Production retains go-smb2 authentication and transport; SRVSVC pagination
// and bounded directory probing are implemented below.
type smbBackend interface {
	dial(context.Context, string, time.Duration) (net.Conn, error)
	authenticate(context.Context, net.Conn, string, *smb2.NTLMInitiator) (smbSession, error)
}

type smbSession interface {
	WithContext(context.Context) smbSession
	Logoff() error
	Mount(string) (smbShare, error)
	ListShares() ([]smbListedShare, error)
}

type smbShare interface {
	WithContext(context.Context) smbShare
	Umount() error
	ReadDir(string) ([]os.FileInfo, error)
	OpenFile(string, int, os.FileMode) (io.Closer, error)
	Remove(string) error
}

type systemSMBBackend struct{}

func (systemSMBBackend) dial(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", target)
}

func (systemSMBBackend) authenticate(ctx context.Context, conn net.Conn, host string, initiator *smb2.NTLMInitiator) (smbSession, error) {
	session, err := (&smb2.Dialer{Initiator: initiator}).DialConn(ctx, conn, host)
	if err != nil {
		return nil, err
	}
	return realSMBSession{Session: session, host: host, ctx: ctx}, nil
}

type realSMBSession struct {
	*smb2.Session
	host string
	ctx  context.Context
}

func (s realSMBSession) WithContext(ctx context.Context) smbSession {
	return realSMBSession{Session: s.Session.WithContext(ctx), host: s.host, ctx: ctx}
}

// The dependency's convenience enumerator ignores the SRVSVC continuation
// status. Keep its authenticated SMB transport, but consume every RPC page.
func (s realSMBSession) ListShares() ([]smbListedShare, error) {
	share, err := s.Session.Mount("IPC$")
	if err != nil {
		return nil, err
	}
	share = share.WithContext(s.ctx)
	defer share.Umount()
	pipe, err := openSMBEnumerationPipe(s.ctx, func() (io.ReadWriteCloser, error) {
		file, err := share.OpenFile("srvsvc", os.O_RDWR, 0o666)
		if err != nil {
			return nil, err
		}
		return smbRPCPipe{file}, nil
	}, waitSMBConnect)
	if err != nil {
		return nil, err
	}
	defer pipe.Close()
	return enumerateSMBShares(pipe, s.host)
}

// A busy/unavailable named-pipe instance is temporary server pressure, not a
// rejected login. Retry only CREATE on the existing IPC$ tree and SMB session.
// Do not restart authentication or replay an enumeration already in progress.
func openSMBEnumerationPipe(ctx context.Context, open func() (io.ReadWriteCloser, error), wait func(context.Context, time.Duration) error) (io.ReadWriteCloser, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pipe, err := open()
		if err == nil {
			return pipe, nil
		}
		if pipe != nil {
			_ = pipe.Close()
		}
		var response *smb2.ResponseError
		if attempt == 3 || !errors.As(err, &response) ||
			(response.Code != 0xc00000ab && response.Code != 0xc00000ac && response.Code != 0xc00000ae) {
			return nil, err
		}
		if err := wait(ctx, (250*time.Millisecond)<<attempt); err != nil {
			return nil, err
		}
	}
}

// Named pipes use zero offsets for each SMB message. File.Read/Write maintain a
// seek position intended for regular files, so use the offset-explicit methods.
type smbRPCPipe struct{ *smb2.File }

func (p smbRPCPipe) Read(b []byte) (int, error)  { return p.ReadAt(b, 0) }
func (p smbRPCPipe) Write(b []byte) (int, error) { return p.WriteAt(b, 0) }

func (s realSMBSession) Mount(name string) (smbShare, error) {
	share, err := s.Session.Mount(name)
	if err != nil {
		return nil, err
	}
	return realSMBShare{share}, nil
}

type realSMBShare struct{ *smb2.Share }

func (s realSMBShare) WithContext(ctx context.Context) smbShare {
	return realSMBShare{s.Share.WithContext(ctx)}
}

func (s realSMBShare) OpenFile(name string, flags int, mode os.FileMode) (io.Closer, error) {
	return s.Share.OpenFile(name, flags, mode)
}

// Only prove directory-list permission. Fetching and sorting every file in a
// large share root can delay this host's entire result without adding evidence.
func (s realSMBShare) ReadDir(name string) ([]os.FileInfo, error) {
	directory, err := s.Share.Open(name)
	if err != nil {
		return nil, err
	}
	return probeSMBDirectory(directory)
}

type smbDirectory interface {
	Readdir(int) ([]os.FileInfo, error)
	Close() error
}

func probeSMBDirectory(directory smbDirectory) ([]os.FileInfo, error) {
	defer directory.Close()
	entries, err := directory.Readdir(1)
	if len(entries) > 0 || errors.Is(err, io.EOF) {
		return entries, nil
	}
	return entries, err
}
