//go:build windows

package adversarial

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// pipeServer returns the process serving the broker pipe for a state root, or
// 0 when nothing is listening. It dials without the "same program" check the
// product client applies (ADR-0021): this is the test asking the OS who is on
// the other end, not a client trusting an answer from it.
func pipeServer(stateRoot string) uint32 {
	timeout := 250 * time.Millisecond
	conn, err := winio.DialPipe(approval.EndpointFor(stateRoot), &timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()
	handle, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(handle.Fd()), &pid); err != nil {
		return 0
	}
	return pid
}

func processImage(process windows.Handle) string {
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(process, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// stopApprovalDaemon terminates the approval daemon that this suite's binary
// spawned for a state root, and waits for it to exit so the image is released.
//
// It refuses to touch any process that is not that binary: the endpoint is
// derived from an isolated temp state root, so a stranger there is not
// expected, but a helper that ends processes checks what it is about to end.
// The build directory's name is compared, not the whole path, because the OS
// reports the long form of a path the runner may have given as an 8.3 name.
func stopApprovalDaemon(t *testing.T, stateRoot string) {
	t.Helper()
	pid := pipeServer(stateRoot)
	if pid == 0 {
		return
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Logf("cannot open the daemon process %d to stop it: %v", pid, err)
		return
	}
	defer windows.CloseHandle(process)
	image := processImage(process)
	if adversarialBuildDir == "" ||
		!strings.EqualFold(filepath.Base(image), filepath.Base(adversarialBinary)) ||
		!strings.EqualFold(filepath.Base(filepath.Dir(image)), filepath.Base(adversarialBuildDir)) {
		t.Logf("not stopping process %d: %q is not this suite's binary", pid, image)
		return
	}
	if err := windows.TerminateProcess(process, 1); err != nil {
		t.Logf("cannot stop the daemon process %d: %v", pid, err)
		return
	}
	if event, _ := windows.WaitForSingleObject(process, 5000); event != windows.WAIT_OBJECT_0 {
		t.Logf("the daemon process %d did not exit within 5s of being stopped", pid)
	}
}
