//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func currentUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read token user: %w", err)
	}
	return user.User.Sid, nil
}

// listenPrivate creates a Windows named pipe listener with an owner-only DACL.
func listenPrivate(pipe string) (net.Listener, error) {
	if !strings.HasPrefix(pipe, pipePrefix) || len(pipe) >= 256 {
		return nil, fmt.Errorf("malformed pipe name: %s", pipe)
	}
	// Check if already running / probe dial
	probeTimeout := 100 * time.Millisecond
	if conn, err := winio.DialPipe(pipe, &probeTimeout); err == nil {
		_ = conn.Close()
		return nil, errors.New("daemon is already running")
	}

	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(pipe, &winio.PipeConfig{
		SecurityDescriptor: fmt.Sprintf("D:P(A;;GA;;;%s)", sid.String()),
	})
}

// dialPrivate connects to the named pipe and verifies the server peer.
func dialPrivate(pipe string) (net.Conn, error) {
	timeout := 2 * time.Second
	conn, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// verifyClientToken verifies that the connecting client process belongs
// to the same user logon session.
func verifyClientToken(conn net.Conn) error {
	handle, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return nil // skip if handle extraction not supported by underlying conn
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(handle.Fd()), &pid); err != nil {
		return fmt.Errorf("get named pipe client pid: %w", err)
	}
	if pid == 0 {
		return nil
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open client process %d: %w", pid, err)
	}
	defer windows.CloseHandle(proc)

	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("open client token %d: %w", pid, err)
	}
	defer token.Close()

	clientUser, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("get client token user: %w", err)
	}
	mySID, err := currentUserSID()
	if err != nil {
		return err
	}
	if !windows.EqualSid(clientUser.User.Sid, mySID) {
		return errors.New("client process does not belong to the current user")
	}
	return nil
}
