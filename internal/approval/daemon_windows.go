//go:build windows

package approval

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func persistentApprovalError() error { return nil }

const pipeNamespace = `\\.\pipe\`

// windowsStateRoot is the per-user state root whose digest names the broker
// pipe, so two Windows user profiles never share a daemon (ADR-0021 §4).
func windowsStateRoot() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "guardrail")
}

// brokerPipeName derives the fixed-length broker pipe name from a state
// root. Named-pipe names are limited to 256 bytes; hashing keeps the name
// at that fixed length no matter how deep the state root is.
func brokerPipeName(stateRoot string) string {
	digest := sha256.Sum256([]byte(stateRoot))
	return pipeNamespace + "guardrail-broker-" + fmt.Sprintf("%x", digest[:8])
}

func defaultPrivateEndpoint() string { return brokerPipeName(windowsStateRoot()) }

// currentUserSID returns the SID of the user running this process; the pipe
// DACL grants access to this SID only, so the OS authenticates every peer.
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

// listenPrivate creates the broker's named pipe with an owner-only DACL —
// the Windows counterpart of the Unix 0700 socket directory. The OS denies
// every other user ERROR_ACCESS_DENIED on connect; no token exists to
// mint, store, or rotate (ADR-0021 §1).
func listenPrivate(pipe string) (net.Listener, error) {
	if pipe == pipeNamespace || !strings.HasPrefix(pipe, pipeNamespace) || len(pipe) >= 256 {
		return nil, ErrMalformed
	}
	// Liveness: named pipes vanish with their process, so the pipe name can
	// only exist while a listener holds it. ERROR_FILE_NOT_FOUND means no
	// listener — there is no stale-socket branch to handle — while a busy
	// pipe or a timed-out dial proves a live daemon owns it (ADR-0021 §1).
	probe := time.Second
	if conn, err := winio.DialPipe(pipe, &probe); err == nil {
		_ = conn.Close()
		return nil, errors.New("approval daemon is already running")
	} else if !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, winio.ErrTimeout) {
			// The pipe name exists — and it can only exist while a
			// listener holds it — but every instance was momentarily
			// busy: a live daemon, saturated for the probe's second.
			return nil, errors.New("approval daemon is already running")
		}
		return nil, fmt.Errorf("check approval pipe owner: %w", err)
	}
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(pipe, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;" + sid.String() + ")",
	})
}

func dialPrivate(pipe string) (net.Conn, error) {
	timeout := time.Second
	return winio.DialPipe(pipe, &timeout)
}
