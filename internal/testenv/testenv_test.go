package testenv

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestChildProcessEnvIncludesEveryRootBeforeOverrides(t *testing.T) {
	t.Setenv("GUARDRAIL_TEST_PARENT", "inherited")
	roots := Roots{Home: "child-home", Config: "child-config", State: "child-state"}
	got := ChildProcessEnv(roots, "LOCALAPPDATA=override-state", "GUARDRAIL_TEST_EXTRA=extra")
	values := map[string]string{}
	for _, assignment := range got {
		name, value, ok := strings.Cut(assignment, "=")
		if ok {
			values[name] = value
		}
	}
	for name, want := range map[string]string{
		"HOME":                  roots.Home,
		"USERPROFILE":           roots.Home,
		"XDG_CONFIG_HOME":       roots.Config,
		"APPDATA":               roots.Config,
		"XDG_STATE_HOME":        roots.State,
		"LOCALAPPDATA":          "override-state",
		"GUARDRAIL_TEST_PARENT": "inherited",
		"GUARDRAIL_TEST_EXTRA":  "extra",
	} {
		if values[name] != want {
			t.Errorf("%s = %q, want %q; env=%q", name, values[name], want, got)
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

func TestPathListRoundTripsHostileExecutableDirectory(t *testing.T) {
	want := filepath.Join(t.TempDir(), "bin with spaces;$(not-run)")
	got := filepath.SplitList(PathList(want))
	if len(got) != 1 || got[0] != want {
		t.Fatalf("SplitList(PathList(%q)) = %q, want one exact entry", want, got)
	}
}

// The helper's whole contract is that the result can actually be created on
// the running host. Asserting the substitution table would only restate the
// code; creating the file is the property.
func TestHostilePathSegmentProducesACreatableName(t *testing.T) {
	segments := []string{
		"repo\npolicy warnings:\nwaivers:\t\x7fdir",
		"guardrail\nforged\t\x7f.toml",
		"repo\nsynced opencode -> forged\t\x1b[31m\x7f\u0080\u009b31m\u009f",
		"a\rb|c?d*e<f>g\"h",
	}
	for _, segment := range segments {
		path := filepath.Join(t.TempDir(), ExecutableName("x")+"-dir")
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(path, HostilePathSegment(segment))
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Errorf("HostilePathSegment(%q) is still not creatable on %s: %v", segment, runtime.GOOS, err)
		}
	}
}

// POSIX must keep the canonical bytes: they are legal there, and they are the
// strongest form of the input the sanitizer has to neutralize.
func TestHostilePathSegmentIsIdentityOnPosix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("substitution applies only on windows")
	}
	const segment = "repo\npolicy warnings:\nwaivers:\t\x1b[31m\x7fdir"
	if got := HostilePathSegment(segment); got != segment {
		t.Errorf("HostilePathSegment altered a POSIX-legal segment: %q -> %q", segment, got)
	}
}

// Every character the helper substitutes in must still be something the
// sanitizer neutralizes or passes through deliberately — otherwise the
// adapted fixture would assert less than the original.
func TestHostilePathSegmentSubstitutesStayHostileOrInert(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("substitution applies only on windows")
	}
	for _, c := range []struct {
		from, to string
		hostile  bool
	}{
		{"\n", "\u2028", true},
		{"\r", "\u2029", true},
		{"\t", "\u00a0", true},
		{"\x1b", "\u009b", true},
		{":", "\ua789", false},
		{">", "\uff1e", false},
	} {
		got := HostilePathSegment("a" + c.from + "b")
		want := "a" + c.to + "b"
		if got != want {
			t.Errorf("HostilePathSegment(%q) = %q, want %q", "a"+c.from+"b", got, want)
		}
	}
}
