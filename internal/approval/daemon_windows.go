//go:build windows

package approval

import (
	"errors"
	"net"
)

func persistentApprovalError() error {
	return errors.New("persistent approvals are unavailable on Windows; use Unix, WSL, or macOS")
}

func listenPrivate(string) (net.Listener, error) { return nil, persistentApprovalError() }

func dialPrivate(string) (net.Conn, error) { return nil, persistentApprovalError() }
