package genconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// A hook command is a string handed to whatever shell the plane's runtime
// uses. An unquoted Windows path does not survive a POSIX one: the
// backslashes are escape characters, `C:\Users\u\bin\guardrail.exe` becomes
// `C:Usersubinguardrail.exe`, the spawn fails, and a PreToolUse hook that
// cannot spawn is a silent no-op. Registered, green in doctor, enforcing
// nothing — measured on a Windows host over four days (#149).
func TestWindowsHookCommandSurvivesAPOSIXShell(t *testing.T) {
	for _, binary := range []string{
		`C:\Users\carlitos\.local\bin\guardrail.exe`,
		`C:\Program Files\guardrail\guardrail.exe`,
		`\\server\share\tools\guardrail.exe`,
	} {
		got := HookCommand(binary, "hook", "claude")
		if strings.Contains(got, `\`) {
			t.Errorf("HookCommand(%q) = %q; a backslash is an escape character in a POSIX shell", binary, got)
		}
		if !strings.HasPrefix(got, `"`) {
			t.Errorf("HookCommand(%q) = %q; the path must be quoted so a space cannot split it", binary, got)
		}
		if !strings.HasSuffix(got, " hook claude") {
			t.Errorf("HookCommand(%q) = %q; the arguments must follow the quoted path", binary, got)
		}
	}
}

// Double quotes and forward slashes are the intersection that cmd.exe and a
// POSIX shell both accept, which is why graft's working hook in the same
// settings file is spelled `node "C:/…/graft-hooks.cjs"`.
func TestWindowsHookCommandUsesTheCrossShellSpelling(t *testing.T) {
	got := HookCommand(`C:\Program Files\guardrail\guardrail.exe`, "hook", "claude")
	want := `"C:/Program Files/guardrail/guardrail.exe" hook claude`
	if got != want {
		t.Fatalf("HookCommand = %q, want %q", got, want)
	}
}

// A POSIX word is left exactly as it was unless a shell would act on it.
// Quoting a clean path or a bare name would rewrite the floor of every POSIX
// install to change nothing — drift, a re-merge, and an approval prompt for
// no safety gain — and would erase the distinction that only opencode pins an
// absolute binary while claude and antigravity resolve a bare name on PATH.
func TestPosixHookCommandLeavesSafeWordsAlone(t *testing.T) {
	for _, binary := range []string{
		"guardrail",
		"guardrail-sentinel",
		"/usr/local/bin/guardrail",
		"/home/u/.local/bin/guardrail",
	} {
		want := binary + " hook claude"
		if got := HookCommand(binary, "hook", "claude"); got != want {
			t.Errorf("HookCommand(%q) = %q, want it unchanged as %q", binary, got, want)
		}
	}
}

// Anything a shell would act on is quoted, single-quoted on POSIX because
// double quotes there still expand `$` and backticks.
func TestPosixHookCommandQuotesWhatAShellWouldActOn(t *testing.T) {
	for _, tt := range []struct{ binary, want string }{
		{"/home/u/my tools/guardrail", `'/home/u/my tools/guardrail' hook claude`},
		{"/home/u/$HOME/guardrail", `'/home/u/$HOME/guardrail' hook claude`},
		{"/home/o'brien/guardrail", `'/home/o'"'"'brien/guardrail' hook claude`},
		{"/home/u/$(whoami)/guardrail", `'/home/u/$(whoami)/guardrail' hook claude`},
		{"/home/u/a;rm -rf ~/guardrail", `'/home/u/a;rm -rf ~/guardrail' hook claude`},
	} {
		if got := HookCommand(tt.binary, "hook", "claude"); got != tt.want {
			t.Errorf("HookCommand(%q) = %q, want %q", tt.binary, got, tt.want)
		}
	}
}

// claude and antigravity concatenated the bare path; the bug was per-plane, so
// the fix is shared or it regrows in whichever plane is added next.
//
// codex is deliberately absent. It already quoted its POSIX command correctly
// and was never part of #149, and its Windows spelling goes through the
// `commandWindows` key that its runtime supports — fix/codex-windows-hook-command
// owns that, not this.
func TestWindowsEveryHookedPlaneQuotesTheBinary(t *testing.T) {
	const binary = `C:\Users\u\.local\bin\guardrail.exe`
	for _, tt := range []struct {
		plane    string
		fragment Fragment
	}{
		{"claude", ClaudeConfig(secretPol(), binary)},
		{"antigravity", AntigravityConfig(binary)},
	} {
		raw, err := json.Marshal(tt.fragment)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, command := range hookCommandsIn(doc) {
			// Only the executable word is inspected: codex appends a failure
			// suffix that legitimately contains an escape sequence.
			executable := leadingWord(command)
			if strings.Contains(executable, `\`) {
				t.Errorf("%s: executable %q carries a backslash", tt.plane, executable)
			}
			// antigravity's runtime spawns `cmd /C` through Go, which turns a
			// quote into \" that cmd cannot read (#353), so a path needing no
			// quotes is emitted bare there.
			want := `"C:/Users/u/.local/bin/guardrail.exe"`
			if tt.plane == "antigravity" {
				want = `C:/Users/u/.local/bin/guardrail.exe`
			}
			if executable != want {
				t.Errorf("%s: executable = %q, want the forward-slashed binary %q", tt.plane, executable, want)
			}
			if hazard := UnquotedShellHazard(command); hazard != "" {
				t.Errorf("%s: command %q is still hazardous: %s", tt.plane, command, hazard)
			}
		}
	}
}

// hookCommandsIn walks any floor shape and yields every hook command string:
// the planes nest them differently (claude at the top, antigravity under a
// "guardrail" key), and this test should not care which.
func hookCommandsIn(node any) []string {
	var out []string
	switch v := node.(type) {
	case map[string]any:
		for key, value := range v {
			if key == "command" {
				if s, ok := value.(string); ok {
					out = append(out, s)
					continue
				}
			}
			out = append(out, hookCommandsIn(value)...)
		}
	case []any:
		for _, item := range v {
			out = append(out, hookCommandsIn(item)...)
		}
	}
	return out
}

// The space detector's old signal was "the token after the first space
// contains a separator", which missed a path whose remainder happens not to:
// `/home/u/my file hook claude` read as safe. #155 shipped with that gap named.
//
// UnquotedShellHazard is only ever called on guardrail's own floor commands,
// and those have a known shape — `<binary> hook <plane> …`. So the question
// stops being the unanswerable "is `a b` a path or a command and an argument"
// and becomes structural: if `hook` is not the word right after the
// executable, the executable was split by a space inside the path.
func TestWindowsUnquotedSpaceIsDetectedByFloorShape(t *testing.T) {
	for _, command := range []string{
		`/home/u/my file hook claude`,
		`/home/u/my dir/g hook claude`,
		`C:/Program Files/g.exe hook claude`,
		`/opt/my tools/guardrail hook antigravity pre`,
		`/home/u/a b c hook codex`,
		`/home/u/my file hook codex || { printf 'x' >&2; exit 2; }`,
	} {
		if got := UnquotedShellHazard(command); got == "" {
			t.Errorf("UnquotedShellHazard(%q) = %q, want a space hazard: the executable is split before `hook`", command, got)
		}
	}
}

// The shapes gen-config actually emits, and the hand-written ones that are
// fine, must stay silent.
func TestWindowsWellFormedFloorCommandsAreNotFlagged(t *testing.T) {
	for _, command := range []string{
		`guardrail hook claude`,
		`guardrail.exe hook claude`,
		`/usr/local/bin/guardrail hook claude`,
		`/usr/local/bin/guardrail hook antigravity pre`,
		`"C:/Users/u/.local/bin/guardrail.exe" hook claude`,
		`'/home/u/my dir/guardrail' hook claude`,
		`'/home/u/g' hook codex || { printf '%s\n' 'x' >&2; exit 2; }`,
		`/usr/local/bin/guardrail hook codex || { printf '%s\n' 'x' >&2; exit 2; }`,
	} {
		if got := UnquotedShellHazard(command); got != "" {
			t.Errorf("UnquotedShellHazard(%q) = %q, want no hazard", command, got)
		}
	}
}

// The boundary, stated as a test rather than only in prose.
//
// A command with no `hook` word is not a shape this function can reason about,
// so it falls back to the weaker separator signal and never invents a hazard.
// And a path whose final component is literally `hook` defeats the structural
// check — contrived, and recorded here so the next reader knows it is a known
// residue rather than an oversight.
func TestWindowsSpaceDetectionAmbiguityBoundary(t *testing.T) {
	// No `hook` word: the separator signal still catches the obvious case.
	if got := UnquotedShellHazard(`/home/u/my dir/g --version`); got == "" {
		t.Error("a path with a space and a separator should still be caught without a `hook` word")
	}
	// No `hook` word and no separator: genuinely ambiguous, so no claim.
	if got := UnquotedShellHazard(`somecmd arg`); got != "" {
		t.Errorf("UnquotedShellHazard(`somecmd arg`) = %q, want no claim on an ambiguous shape", got)
	}
	// Known residue: a path ending in `hook`.
	if got := UnquotedShellHazard(`/home/u/my hook hook claude`); got != "" {
		t.Logf("residue now detected (%q) — the boundary comment can be tightened", got)
	}
}
