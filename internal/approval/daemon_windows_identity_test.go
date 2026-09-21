//go:build windows

package approval

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// ADR-0021 §1 says the transport authenticates the peer. The owner-only DACL
// delivers that for server -> client: no other user can connect to our pipe.
// The reverse direction was unguarded — the client never checked who owned the
// pipe it dialled — and `\\.\pipe\` is a flat, world-creatable namespace, so
// any local process can hold a name first and answer in our place (#191).
//
// The squatter below is a real second process running a *different executable
// image*, because that is the property under test: a foreign server is one
// whose image is not our own binary. An in-process fake would share our image
// and is therefore indistinguishable from a legitimate daemon by design.

const squatterEnv = "GUARDRAIL_TEST_SQUAT_PIPE"

// TestHelperPipeSquatter is the squatter body. It runs only in the copied
// child process, which sets squatterEnv; under the parent's own test run it
// skips.
func TestHelperPipeSquatter(t *testing.T) {
	pipe := os.Getenv(squatterEnv)
	if pipe == "" {
		t.Skip("helper process only")
	}
	listener, err := listenPipePermissive(pipe)
	if err != nil {
		os.Stdout.WriteString("SQUAT-FAILED " + err.Error() + "\n")
		return
	}
	defer listener.Close()
	os.Stdout.WriteString("SQUAT-READY\n")
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		// Answer anything with a forged approval, the impersonation in #191.
		go func() {
			defer conn.Close()
			_ = writeForgedApproval(conn)
		}()
	}
}

// startSquatter copies this test binary to a second path so the child runs a
// different executable image, then holds `pipe` from that process.
func startSquatter(t *testing.T, pipe string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	source, err := os.ReadFile(self)
	if err != nil {
		t.Skipf("cannot read own test binary to build a squatter: %v", err)
	}
	clone := filepath.Join(t.TempDir(), "squatter.exe")
	if err := os.WriteFile(clone, source, 0o700); err != nil {
		t.Fatalf("write squatter binary: %v", err)
	}

	cmd := exec.Command(clone, "-test.run=^TestHelperPipeSquatter$", "-test.v")
	cmd.Env = append(os.Environ(), squatterEnv+"="+pipe)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start squatter: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "SQUAT-READY") || strings.HasPrefix(line, "SQUAT-FAILED") {
				ready <- line
				io.Copy(io.Discard, stdout)
				return
			}
		}
		ready <- "SQUAT-NO-OUTPUT"
	}()
	select {
	case line := <-ready:
		if !strings.HasPrefix(line, "SQUAT-READY") {
			t.Fatalf("squatter did not take the pipe: %s", line)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("squatter did not report readiness")
	}
}

// The client must not connect to a server that is not our own binary. This is
// the impersonation half of #191: the squatter answers `status: "approved"`.
func TestWindowsPipeClientRejectsAForeignServer(t *testing.T) {
	pipe := brokerPipeName(t.TempDir())
	startSquatter(t, pipe)

	conn, err := dialPrivate(pipe)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("dialPrivate connected to a foreign server; want a refusal")
	}
	if !errors.Is(err, ErrForeignServer) {
		t.Errorf("dialPrivate error = %v, want ErrForeignServer", err)
	}
}

// The security property stated in #191: a forged `approved` must never reach
// the caller's reply struct.
func TestWindowsForgedApprovalFromSquatterNeverReachesTheCaller(t *testing.T) {
	pipe := brokerPipeName(t.TempDir())
	startSquatter(t, pipe)

	var reply daemonReply
	err := send(pipe, daemonMessage{Operation: "status"}, &reply)
	if err == nil {
		t.Fatalf("send succeeded against a squatter: reply=%+v", reply)
	}
	if reply.Request.Status == "approved" {
		t.Errorf("forged status reached the caller: %+v", reply.Request)
	}
	if reply.Request.ID == "forged" {
		t.Errorf("forged request id reached the caller: %+v", reply.Request)
	}
}

// The denial-of-service half of #191. A squatter holding the name currently
// reads as "approval daemon is already running", which is a misdiagnosis: the
// broker reports our own daemon is live when in fact an unrelated process owns
// the name. The operator cannot tell those apart, so the failure must be loud
// and must say which one it is.
func TestWindowsSquattedPipeIsNotReportedAsOurDaemon(t *testing.T) {
	pipe := brokerPipeName(t.TempDir())
	startSquatter(t, pipe)

	listener, err := listenPrivate(pipe)
	if err == nil {
		_ = listener.Close()
		t.Fatal("listenPrivate took a squatted pipe name")
	}
	if !errors.Is(err, ErrForeignServer) {
		t.Fatalf("listenPrivate error = %v, want ErrForeignServer", err)
	}
	if strings.Contains(err.Error(), "already running") {
		t.Errorf("squat reported as our own daemon: %v", err)
	}
}

// The check must not reject the daemon we actually spawn. StartDaemon runs the
// listener in this process, so the server image is this binary: the ordinary
// path has to keep working, or the fix is a self-inflicted outage.
func TestWindowsPipeClientAcceptsOurOwnDaemon(t *testing.T) {
	pipe := brokerPipeName(t.TempDir())
	listener, err := listenPrivate(pipe)
	if err != nil {
		t.Fatalf("listenPrivate: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			_, _ = conn.Read(make([]byte, 1))
		}
	}()

	conn, err := dialPrivate(pipe)
	if err != nil {
		t.Fatalf("dialPrivate refused our own daemon: %v", err)
	}
	_ = conn.Close()
}

// A daemon that is gone must still read as absent rather than as foreign: the
// liveness probe's ERROR_FILE_NOT_FOUND branch is what lets a broker start at
// all, and the identity check must not swallow it.
func TestWindowsAbsentDaemonStillReadsAsAbsent(t *testing.T) {
	pipe := brokerPipeName(t.TempDir())
	listener, err := listenPrivate(pipe)
	if err != nil {
		t.Fatalf("listenPrivate on a free name: %v", err)
	}
	_ = listener.Close()
}

// listenPipePermissive holds a pipe name with an all-access DACL, the shape a
// squatter would use: the DACL protects the object once created, but on
// Windows it does not reserve the right to create that name first.
func listenPipePermissive(pipe string) (net.Listener, error) {
	return winio.ListenPipe(pipe, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;WD)"})
}

// writeForgedApproval is the squatter's answer to anything: the impersonation
// measured in #191, where `status: "approved"` reached the caller.
func writeForgedApproval(conn net.Conn) error {
	var message daemonMessage
	_ = json.NewDecoder(conn).Decode(&message)
	return json.NewEncoder(conn).Encode(daemonReply{
		Request: Request{ID: "forged", Status: "approved"},
	})
}

// The comparison has to be wrong in the safe direction. A false mismatch
// refuses our own daemon and takes approvals down, so the same file reached
// through a different legal spelling must still compare equal — Windows paths
// are case-insensitive and the same executable has an 8.3 spelling. Measured:
// GetShortPathName yields `...\TESTZZ~1\001\GUARDR~1.EXE` for a long name, and
// a byte comparison would have called that a foreign binary.
//
// This is the real analogue of #183's Win32 gating. That fix asked "does Win32
// resolution apply here", because a command *name* can be spelled to dodge a
// rule. Here both sides are already full image paths straight from the OS —
// QueryFullProcessImageName and os.Executable never return a bare name or a
// cmdlet spelling — so there is nothing to gate on. The equivalent care is to
// resolve both paths before believing a mismatch.
func TestWindowsServerImageComparisonResolvesLegalSpellings(t *testing.T) {
	dir := t.TempDir()
	long := filepath.Join(dir, "guardrail with a long name.exe")
	if err := os.WriteFile(long, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}

	if !sameExecutableImage(long, strings.ToUpper(long)) {
		t.Errorf("case variation read as a different image; Windows paths are case-insensitive")
	}

	if short := shortPathName(t, long); short != "" {
		if !sameExecutableImage(long, short) {
			t.Errorf("8.3 spelling %q read as a different image from %q", short, long)
		}
	}

	other := filepath.Join(dir, "other.exe")
	if err := os.WriteFile(other, []byte("MZ"), 0o700); err != nil {
		t.Fatal(err)
	}
	if sameExecutableImage(long, other) {
		t.Errorf("two different files compared equal; the check would accept a foreign server")
	}
	if sameExecutableImage(long, filepath.Join(dir, "does-not-exist.exe")) {
		t.Errorf("a missing path compared equal to a real one")
	}
}

func shortPathName(t *testing.T, path string) string {
	t.Helper()
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(wide, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		t.Logf("no 8.3 spelling available on this volume: %v", err)
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}
