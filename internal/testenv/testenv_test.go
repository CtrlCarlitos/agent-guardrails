package testenv

import (
	"os"
	"runtime"
	"testing"
)

func TestSandboxSynchronizesPortableAndWindowsRoots(t *testing.T) {
	roots := Sandbox(t)

	for name, want := range map[string]string{
		"HOME":            roots.Home,
		"USERPROFILE":     roots.Home,
		"XDG_CONFIG_HOME": roots.Config,
		"APPDATA":         roots.Config,
		"XDG_STATE_HOME":  roots.State,
		"LOCALAPPDATA":    roots.State,
	} {
		if got := os.Getenv(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestSettersKeepEquivalentRootsTogether(t *testing.T) {
	SetHome(t, "home")
	SetConfig(t, "config")
	SetState(t, "state")

	for name, want := range map[string]string{
		"HOME":            "home",
		"USERPROFILE":     "home",
		"XDG_CONFIG_HOME": "config",
		"APPDATA":         "config",
		"XDG_STATE_HOME":  "state",
		"LOCALAPPDATA":    "state",
	} {
		if got := os.Getenv(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// The suffix is the host's, not the target's: these helpers name a file this
// process is about to build and then execute, so the only correct answer is
// what the running platform can exec.
func TestExecutableNameCarriesTheHostSuffix(t *testing.T) {
	got := ExecutableName("guardrail")
	want := "guardrail"
	if runtime.GOOS == "windows" {
		want = "guardrail.exe"
	}
	if got != want {
		t.Errorf("ExecutableName(%q) = %q, want %q on %s", "guardrail", got, want, runtime.GOOS)
	}
}

// A name that already carries the suffix must not collect a second one:
// `guardrail.exe.exe` is a different filename, and Windows will not run it
// (measured in #178).
func TestExecutableNameIsIdempotentOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("suffix only applies on windows")
	}
	if got := ExecutableName(ExecutableName("guardrail")); got != "guardrail.exe" {
		t.Errorf("double application = %q, want %q", got, "guardrail.exe")
	}
}
