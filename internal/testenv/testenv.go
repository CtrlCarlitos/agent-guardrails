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

// hostileWindowsNameBytes maps characters that are hostile to a line-oriented
// report but illegal in a Windows filename onto ones that are both hostile and
// legal. Measured on Windows 11 / NTFS: \n, \r, \t and ESC are rejected by the
// filesystem, while U+2028, U+2029, U+00A0 and the C1 controls (U+0080-U+009F,
// including U+007F) are accepted.
//
// Each substitution preserves what the sanitizer has to do with it, so the
// expected display string is unchanged:
//
//	\n   -> U+2028 LINE SEPARATOR       breaks a line; unicode.IsSpace
//	\r   -> U+2029 PARAGRAPH SEPARATOR  breaks a line; unicode.IsSpace
//	\t   -> U+00A0 NO-BREAK SPACE       column-shifting; unicode.IsSpace
//	\x1b -> U+009B CSI                  the C1 single-character form of ESC [
//
// The ESC substitution is the faithful one rather than a convenience: U+009B
// *is* the control-sequence introducer, so a Windows filename carrying it is
// the same terminal-injection attack the POSIX fixture spells with ESC [.
// The punctuation below is a second, different category. None of it is
// hostile to a report \u2014 it is inert, and the sanitizer passes it through
// unchanged on every platform \u2014 but Windows reserves all of it in a filename,
// so a fixture spelling a forged `policy warnings:` line or a `synced x -> y`
// status line cannot create the file at all. Each maps to a printable
// look-alike that NTFS accepts (measured: every ASCII form below is rejected
// and every substitute accepted).
//
// Because these are inert, the same substitution applies to the *expected*
// display string as to the fixture, and that does not weaken the assertion:
// the sanitizer is still the only thing neutralizing the newline, tab, escape,
// DEL and C1 bytes, which is the property under test. What changes is only
// which harmless glyph sits between them.
var hostileWindowsNameBytes = strings.NewReplacer(
	// Hostile, and illegal on Windows: substitute keeps the hostility.
	"\n", "\u2028",
	"\r", "\u2029",
	"\t", "\u00a0",
	"\x1b", "\u009b",
	// Inert, but reserved by Windows: substitute is cosmetic.
	":", "\ua789",
	">", "\uff1e",
	"<", "\uff1c",
	`"`, "\uff02",
	"|", "\uff5c",
	"?", "\uff1f",
	"*", "\uff0a",
)

// HostilePathSegment adapts a deliberately hostile path segment to what this
// host will accept in a filename, without softening what it tests.
//
// Fixtures that assert output sanitization build real files whose names carry
// newlines, tabs and escapes, so a path can try to forge an extra status line
// in a report. Windows cannot create those names at all, so the fixture failed
// at os.Mkdir long before reaching the assertion and the sanitizer went
// unexercised on the platform whose console rendering differs most (#174,
// family K).
//
// POSIX keeps the canonical bytes. Gating these tests off on Windows would
// have been the cheaper fix and the wrong one: the property under test is that
// the *product* neutralizes hostile bytes in its own output, which does not
// require those exact bytes to survive a round trip through the filesystem.
func HostilePathSegment(segment string) string {
	if runtime.GOOS != "windows" {
		return segment
	}
	return hostileWindowsNameBytes.Replace(segment)
}
