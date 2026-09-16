//go:build !windows

package approval

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return net.Listen("unix", socket)
}

func dialPrivate(socket string) (net.Conn, error) { return net.Dial("unix", socket) }
