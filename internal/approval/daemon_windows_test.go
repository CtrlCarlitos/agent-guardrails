//go:build windows

package approval

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// uniquePipeName returns an unused pipe name for test isolation.
func uniquePipeName(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "grdpipe")
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(dir)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return `\\.\pipe\guardrail-test-` + base
}

func currentUserSIDString(t *testing.T) string {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("current user SID: %v", err)
	}
	return sid.String()
}

// TestWindowsDefaultSocketPathDerivesPipeName pins the ADR-0021 pipe-name
// shape: \\.\pipe\guardrail-broker-<16 hex chars> derived from the
// LOCALAPPDATA state root, so two Windows user profiles never share a broker.
func TestWindowsDefaultSocketPathDerivesPipeName(t *testing.T) {
	t.Setenv("LOCALAPPDATA", filepath.Join(t.TempDir(), "state"))
	name := DefaultSocketPath()
	if !strings.HasPrefix(name, `\\.\pipe\guardrail-broker-`) {
		t.Fatalf("DefaultSocketPath() = %q, want \\\\.\\pipe\\guardrail-broker- prefix", name)
	}
	suffix := strings.TrimPrefix(name, `\\.\pipe\guardrail-broker-`)
	if len(suffix) != 16 || strings.ToLower(suffix) != suffix {
		t.Fatalf("pipe name suffix = %q, want 16 lowercase hex characters", suffix)
	}
}

// TestWindowsPipeNameIndependentOfStateRootDepth pins the property the
// assignment requires: the pipe name is a fixed-length digest of the state
// root, so a deep state root cannot exceed \\.\pipe\ name limits.
func TestWindowsPipeNameIndependentOfStateRootDepth(t *testing.T) {
	shallow := brokerPipeName(`C:\u\s`)
	deep := brokerPipeName(`C:\` + strings.Repeat("very-deep-state-", 500))
	if len(shallow) != len(deep) {
		t.Fatalf("pipe name length depends on state root depth: shallow=%d deep=%d", len(shallow), len(deep))
	}
	for _, name := range []string{shallow, deep} {
		if !strings.HasPrefix(name, `\\.\pipe\`) {
			t.Fatalf("pipe name %q lacks the \\\\.\\pipe\\ prefix", name)
		}
		if len(name) >= 256 {
			t.Fatalf("pipe name %q exceeds the 256-byte named-pipe limit", len(name))
		}
	}
	if shallow == deep {
		t.Fatal("distinct state roots must derive distinct pipe names")
	}

	t.Setenv("LOCALAPPDATA", `C:\`+strings.Repeat("very-deep-state-", 500))
	if name := DefaultSocketPath(); len(name) != len(shallow) {
		t.Fatalf("DefaultSocketPath() length = %d for a deep state root, want the fixed %d", len(name), len(shallow))
	}
}

// TestWindowsListenPrivateRejectsNonPipeNames mirrors the Unix seam's
// absolute-path validation: only pipe-namespace names are accepted.
func TestWindowsListenPrivateRejectsNonPipeNames(t *testing.T) {
	for _, bad := range []string{"", "C:\\tmp\\broker.sock", "broker.sock", `\\.\pipe\`} {
		if _, err := listenPrivate(bad); !errors.Is(err, ErrMalformed) {
			t.Fatalf("listenPrivate(%q) error = %v, want ErrMalformed", bad, err)
		}
	}
}

// TestWindowsListenDialRoundTrip exercises the byte-stream transport end to
// end: listen, dial, one JSON message each way.
func TestWindowsListenDialRoundTrip(t *testing.T) {
	pipe := uniquePipeName(t)
	listener, err := listenPrivate(pipe)
	if err != nil {
		t.Fatalf("listenPrivate: %v", err)
	}
	defer listener.Close()

	type served struct {
		conn net.Conn
		err  error
	}
	done := make(chan served, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- served{nil, err}
			return
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- served{nil, err}
			return
		}
		var message map[string]any
		if err := json.NewDecoder(conn).Decode(&message); err != nil {
			done <- served{nil, err}
			return
		}
		if err := json.NewEncoder(conn).Encode(message); err != nil {
			done <- served{nil, err}
			return
		}
		done <- served{conn, nil}
	}()

	client, err := dialPrivate(pipe)
	if err != nil {
		t.Fatalf("dialPrivate: %v", err)
	}
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"operation": "submit", "id": "win-1"}
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	if err := json.NewDecoder(client).Decode(&request); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if request["operation"] != "submit" || request["id"] != "win-1" {
		t.Fatalf("echoed request = %+v, want the written message", request)
	}
	select {
	case s := <-done:
		if s.err != nil {
			t.Fatalf("server side failed: %v", s.err)
		}
		s.conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("echo server did not finish")
	}
}

// TestWindowsListenPrivateRefusesWhenPipeLive pins liveness semantics: a
// successful dial means a daemon owns the pipe, and a second listener must
// not replace it.
func TestWindowsListenPrivateRefusesWhenPipeLive(t *testing.T) {
	pipe := uniquePipeName(t)
	first, err := listenPrivate(pipe)
	if err != nil {
		t.Fatalf("first listenPrivate: %v", err)
	}
	defer first.Close()
	_, err = listenPrivate(pipe)
	if err == nil {
		t.Fatal("second listenPrivate succeeded over a live pipe")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second listenPrivate error = %v, want already-running", err)
	}
}

// TestWindowsDialPrivateReportsMissingPipe pins not-running semantics: with
// no listener, dial fails as not-exist. Named pipes vanish with their
// process, so no stale-file branch exists (ADR-0021 §1).
func TestWindowsDialPrivateReportsMissingPipe(t *testing.T) {
	_, err := dialPrivate(uniquePipeName(t))
	if err == nil {
		t.Fatal("dialPrivate succeeded with no listener")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dialPrivate error = %v, want os.ErrNotExist", err)
	}
}

// TestWindowsPipeOwnerOnlyDACL asserts the security property the OS uses to
// authenticate the peer — the Windows counterpart of the Unix 0700 socket
// directory — by reading the pipe handle's security info: owner SID and a
// single allow ACE, both the current user's SID.
func TestWindowsPipeOwnerOnlyDACL(t *testing.T) {
	pipe := uniquePipeName(t)
	listener, err := listenPrivate(pipe)
	if err != nil {
		t.Fatalf("listenPrivate: %v", err)
	}
	defer listener.Close()

	// A client handle requires a pending Accept: the pipe's instances are
	// created by the listener per Accept, so hold one open while the
	// security info is read from the connected handle.
	type accepted struct {
		conn net.Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		done <- accepted{conn, err}
	}()

	namePtr, err := windows.UTF16PtrFromString(pipe)
	if err != nil {
		t.Fatal(err)
	}
	var handle windows.Handle
	deadline := time.Now().Add(2 * time.Second)
	for {
		handle, err = windows.CreateFile(namePtr, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("open pipe handle: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer windows.CloseHandle(handle)

	sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetSecurityInfo: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}

	wantSID := currentUserSIDString(t)
	if owner == nil || owner.String() != wantSID {
		t.Fatalf("pipe owner = %v, want current user %s", owner, wantSID)
	}
	if dacl == nil {
		t.Fatal("pipe DACL is null")
	}
	if dacl.AceCount != 1 {
		t.Fatalf("pipe DACL has %d ACEs, want exactly 1", dacl.AceCount)
	}
	ace := (*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + 8))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("ACE type = %d, want ACCESS_ALLOWED_ACE_TYPE", ace.Header.AceType)
	}
	// GENERIC_ALL in the SDDL materializes as FILE_ALL_ACCESS (0x1F01FF)
	// on the pipe object: every access right, the owner-only grant.
	const fileAllAccess = 0x1F01FF
	if ace.Mask != fileAllAccess && ace.Mask != windows.GENERIC_ALL {
		t.Fatalf("ACE mask = %#x, want FILE_ALL_ACCESS/GENERIC_ALL", ace.Mask)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if aceSID.String() != wantSID {
		t.Fatalf("ACE SID = %s, want current user %s", aceSID.String(), wantSID)
	}
	if a := <-done; a.err != nil {
		t.Fatalf("pending accept failed: %v", a.err)
	} else {
		a.conn.Close()
	}
}
