//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// listenPrivate creates a Unix domain socket listener with 0700 permissions.
func listenPrivate(socketPath string) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}

	// If socket already exists, probe dial
	if conn, err := net.Dial("unix", socketPath); err == nil {
		_ = conn.Close()
		return nil, errors.New("daemon is already running")
	} else {
		// Clean up dead socket
		_ = os.Remove(socketPath)
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(socketPath, 0o600)
	return l, nil
}

// dialPrivate connects to the Unix domain socket.
func dialPrivate(socketPath string) (net.Conn, error) {
	return net.Dial("unix", socketPath)
}

func verifyClientToken(_ net.Conn) error {
	return nil
}
