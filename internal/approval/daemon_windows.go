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
//
// On the name-squatting half of #191, the intended mechanism was
// FILE_FLAG_FIRST_PIPE_INSTANCE, which makes the create fail outright when the
// name already exists. go-winio's ListenPipe does not expose that flag, and
// the choice here is the probe shape over a winio fork, because measurement
// showed the flag would buy less than it appears:
//
//   - With a squatter already holding the name, a second winio.ListenPipe is
//     refused with ERROR_ACCESS_DENIED regardless — Windows checks the
//     existing pipe's DACL for create-instance rights. We never silently
//     attach to a foreign name.
//   - The defect was therefore never silent acceptance; it was the
//     *misdiagnosis* below, which reported a squatter as our own live daemon.
//     Identifying the serving image fixes that, and the flag would not have.
//
// What the flag would still close, and this does not: the window between the
// probe and the create. A process that takes the name in that gap is not
// caught here, and the create then fails with a bare access-denied rather than
// a named squat. Closing that needs the atomic create, so it needs the flag,
// so it needs a fork — deliberately not taken for a race an attacker cannot
// aim at, while the durable hole (a squatter already in place) is closed.
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
		// The name is held. Whether that is our daemon or a squatter is the
		// difference between "nothing to do" and "someone is impersonating the
		// broker", and the operator cannot act on the two the same way, so the
		// answer comes from the serving image rather than from the name.
		foreign := verifyServerIsOurBinary(conn)
		_ = conn.Close()
		if foreign != nil {
			return nil, foreign
		}
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
	conn, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		return nil, err
	}
	if err := verifyServerIsOurBinary(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// serverImagePath asks the OS which executable is serving the other end of a
// client pipe connection. This is the peer answer the flat `\\.\pipe\`
// namespace denies us by name alone: the name proves nothing, the serving
// process does (#191).
//
// The handle is reached through an `Fd() uintptr` assertion because winio
// returns a bare net.Conn over an unexported type. That is not part of winio's
// documented API, so it is treated as load-bearing: if an upgrade removes the
// method every dial fails closed, and TestWindowsPipeClientAcceptsOurOwnDaemon
// turns red rather than the check silently passing everything.
func serverImagePath(conn net.Conn) (string, error) {
	handle, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return "", fmt.Errorf("%w: pipe connection %T exposes no handle to identify the peer", ErrForeignServer, conn)
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(handle.Fd()), &pid); err != nil {
		return "", fmt.Errorf("%w: cannot read the serving process id: %v", ErrForeignServer, err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("%w: cannot open the serving process %d: %v", ErrForeignServer, pid, err)
	}
	defer windows.CloseHandle(process)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(process, 0, &buf[0], &size); err != nil {
		return "", fmt.Errorf("%w: cannot read the serving image path for %d: %v", ErrForeignServer, pid, err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// verifyServerIsOurBinary refuses a peer that is not running this executable.
//
// Our own binary is the right comparand rather than a configured path because
// SubmitOnDemand spawns the daemon as `os.Args[0] approvals daemon` — the
// daemon *is* this program, so any other image on that pipe is by definition
// not the daemon we would have started.
//
// Boundary, stated because it is the reason this is not the whole answer: a
// process running as the same user can copy this binary and pass the check.
// That cell of the threat model is open on Unix too — a same-user process can
// bind the socket path there first — and closing it needs a decision recorded
// on #191 rather than a check here.
func verifyServerIsOurBinary(conn net.Conn) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: cannot identify this executable: %v", ErrForeignServer, err)
	}
	image, err := serverImagePath(conn)
	if err != nil {
		return err
	}
	if sameExecutableImage(self, image) {
		return nil
	}
	return fmt.Errorf("%w: pipe is served by %q, not %q", ErrForeignServer, image, self)
}

// sameExecutableImage compares two Win32 image paths. Windows paths are
// case-insensitive, and the same file can be reached through a link or a
// short (8.3) spelling, so a byte mismatch is resolved before it is believed
// — the comparison has to be wrong in the safe direction, and a false
// mismatch would refuse our own daemon.
func sameExecutableImage(a, b string) bool {
	if strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
		return true
	}
	resolvedA, errA := filepath.EvalSymlinks(a)
	resolvedB, errB := filepath.EvalSymlinks(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(resolvedA), filepath.Clean(resolvedB))
}
