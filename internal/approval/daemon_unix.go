//go:build !windows

package approval

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func persistentApprovalError() error { return nil }

func listenPrivate(socket string) (net.Listener, error) {
	if socket == "" || !filepath.IsAbs(socket) {
		return nil, ErrMalformed
	}
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create approval socket directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure approval socket directory: %w", err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("approval socket directory is not private")
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("approval socket path is not a socket")
		}
		conn, dialErr := net.DialTimeout("unix", socket, time.Second)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("approval daemon is already running")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("check approval socket owner: %w", dialErr)
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return net.Listen("unix", socket)
}

func dialPrivate(socket string) (net.Conn, error) { return net.Dial("unix", socket) }
