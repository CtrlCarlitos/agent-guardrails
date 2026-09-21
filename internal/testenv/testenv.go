// Package testenv keeps test-owned home, config, and state roots consistent
// across the Unix XDG and Windows environment conventions.
package testenv

import (
	"runtime"
	"strings"
)

// TB is the part of testing.TB needed by the environment helpers.
type TB interface {
	Helper()
	Setenv(string, string)
	TempDir() string
}

// Roots contains the three independent filesystem roots used by Sandbox.
type Roots struct {
	Home   string
	Config string
	State  string
}

// Sandbox points every supported home, config, and state variable at fresh
// test-owned directories. Tests that need a specific root can use the setters.
func Sandbox(t TB) Roots {
	t.Helper()
	roots := Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
	SetHome(t, roots.Home)
	SetConfig(t, roots.Config)
	SetState(t, roots.State)
	return roots
}

// SetHome synchronizes the Unix and Windows home variables.
func SetHome(t TB, root string) {
	t.Helper()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
}

// SetConfig synchronizes the XDG and Windows roaming-config roots.
func SetConfig(t TB, root string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv("APPDATA", root)
}

// SetState synchronizes the XDG and Windows local-state roots.
func SetState(t TB, root string) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", root)
	t.Setenv("LOCALAPPDATA", root)
}

// ExecutableName returns base with the executable suffix the host requires.
//
// A test that builds a helper binary with `go build -o <dir>/guardrail` gets a
// file spelled exactly that on every platform: Go does not append `.exe` when
// -o names a file. Windows then refuses to run it, because an executable is
// resolved through PATHEXT and a name with no extension is not in it. The
// error says `executable file not found in %PATH%` even for an absolute path
// that exists, which reads as an environment problem rather than a missing
// suffix -- the reason this went unnoticed long enough for the adversarial
// corpus never to have run on Windows at all (#198).
func ExecutableName(base string) string {
	if runtime.GOOS != "windows" {
		return base
	}
	if strings.EqualFold(filepathExt(base), ".exe") {
		// Applying the suffix twice yields `guardrail.exe.exe`, which is a
		// different filename Windows will not run (measured in #178).
		return base
	}
	return base + ".exe"
}

// filepathExt is path/filepath.Ext without the import cycle risk of pulling
// filepath into a helper this small; it only ever sees a bare file name.
func filepathExt(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i:]
	}
	return ""
}

// ChildRootEnv returns the environment assignments that point a spawned
// process's home, config, and state roots at test-owned directories.
//
// Sandbox does this for the running process through t.Setenv; a test that
// execs the built binary has to pass the same roots down explicitly, and the
// two must agree. Setting only the XDG names is the failure this exists to
// prevent: on Windows the child reads APPDATA and LOCALAPPDATA instead, so it
// silently writes its audit log and state into the operator's real profile
// while the test looks in its temp directory and finds nothing (#198).
//
// Append these after inherited variables so they win, and append any
// deliberate per-test override after these.
func ChildRootEnv(roots Roots) []string {
	return []string{
		"HOME=" + roots.Home,
		"USERPROFILE=" + roots.Home,
		"XDG_CONFIG_HOME=" + roots.Config,
		"APPDATA=" + roots.Config,
		"XDG_STATE_HOME=" + roots.State,
		"LOCALAPPDATA=" + roots.State,
	}
}
