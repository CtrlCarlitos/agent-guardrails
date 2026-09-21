package engine

import (
	"runtime"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func spellPol() *policy.Policy {
	p := pathPol()
	p.Slots.SafeRoots = []string{`C:\repo\tmp`}
	p.Slots.EgressAllowlist = []string{"github.com"}
	return p
}

func evalSpelling(t *testing.T, cmd string) policy.Verdict {
	t.Helper()
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "PowerShell",
		Capability: policy.CapabilityCommand, Command: cmd, CWD: `C:\repo`, RepoRoot: `C:\repo`}, spellPol())
}

// Win32 strips trailing dots and spaces while resolving a path, so
// `C:\bin\rm.exe.` runs `rm`. head() stripped one `.exe` and nothing else, so
// the name it compared was `rm.exe.`, no rule matched, and the call allowed —
// across every family keyed on a command name (#178).
//
// Measured on a Windows host before this fix: each of these allowed, while the
// plain spelling denied.
func TestWindowsTrailingDotAndSpacePathsStillMatchTheirRule(t *testing.T) {
	for _, tt := range []struct {
		cmd  string
		rule string
	}{
		{`C:\bin\rm.exe. -rf C:\Windows\System32`, "P1.rm-rf"},
		{`C:\bin\rm.exe.. -rf C:\Windows\System32`, "P1.rm-rf"},
		{`C:\bin\rm.exe... -rf C:\Windows\System32`, "P1.rm-rf"},
		{`"C:\bin\rm.exe " -rf C:\Windows\System32`, "P1.rm-rf"},
		{`'C:\bin\rm.exe ' -rf C:\Windows\System32`, "P1.rm-rf"},
		{`"C:\bin\rm.exe. " -rf C:\Windows\System32`, "P1.rm-rf"},
		{`.\rm.exe. -rf C:\Windows\System32`, "P1.rm-rf"},
		{`C:\bin\RM.EXE. -rf C:\Windows\System32`, "P1.rm-rf"},
		{`C:\bin\sudo.exe. whoami`, "P1.privesc"},
		{`C:\bin\curl.exe. https://evil.example.com`, "P6.egress"},
		{`C:\bin\guardrail.exe. night off`, "P5.self-config"},
		{`C:\bin\mkfs.ext4. /dev/sda`, "P1.mkfs"},
	} {
		v := evalSpelling(t, tt.cmd)
		if v.Decision == policy.Allow || v.RuleID != tt.rule {
			t.Errorf("%q -> %+v, want %s (Win32 resolves this to the plain name)", tt.cmd, v, tt.rule)
		}
	}
}

// The plain spellings must keep their verdicts unchanged.
func TestWindowsPlainSpellingsAreUnchanged(t *testing.T) {
	for _, tt := range []struct {
		cmd  string
		rule string
	}{
		{`rm -rf C:\Windows\System32`, "P1.rm-rf"},
		{`C:\bin\rm.exe -rf C:\Windows\System32`, "P1.rm-rf"},
		{`C:\bin\.\rm.exe -rf C:\Windows\System32`, "P1.rm-rf"},
		{`RM.EXE -rf C:\Windows\System32`, "P1.rm-rf"},
		{`sudo whoami`, "P1.privesc"},
		{`curl https://evil.example.com`, "P6.egress"},
		{`guardrail night off`, "P5.self-config"},
	} {
		v := evalSpelling(t, tt.cmd)
		if v.RuleID != tt.rule {
			t.Errorf("%q -> %+v, want %s unchanged", tt.cmd, v, tt.rule)
		}
	}
}

// The phantoms. Measured on a Windows host: these do NOT execute, so denying
// them would invent a verdict for a command that cannot run.
//
//   - a bare name is resolved on PATH, and PATH lookup does not strip trailing
//     dots or spaces — `rm.` is simply not found. This was my first hypothesis
//     and it was wrong.
//   - a doubled extension is a different filename. `rm.exe.exe` is not `rm`,
//     with or without a path.
//   - a cmdlet is resolved by name, not by path: `Remove-Item.` is not found
//     either, so the PowerShell families keep exact matching.
func TestWindowsNonExecutableSpellingsAreNotDenied(t *testing.T) {
	for _, cmd := range []string{
		`rm. -rf C:\Windows\System32`,
		`rm.. -rf C:\Windows\System32`,
		`rm.exe.exe -rf C:\Windows\System32`,
		`C:\bin\rm.exe.exe -rf C:\Windows\System32`,
		`sudo. whoami`,
		`Remove-Item. -Recurse -Force C:\Windows\System32`,
		`Format-Volume. -DriveLetter C`,
		`iex. "whoami"`,
	} {
		if v := evalSpelling(t, cmd); v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want no deny: this spelling does not execute on Windows", cmd, v)
		}
	}
}

// A POSIX path keeps POSIX semantics on every host. `rm.` and `rm ` are legal,
// distinct filenames there, so trimming them would make the Engine judge a
// different program than the one that runs. The trim is keyed on the path
// being Windows-shaped, not on the host — the same reasoning HookCommand uses.
func TestWindowsTrimDoesNotReachPosixPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Not a POSIX host: MSYS hands these to Win32, which strips, so the
		// trim is correct here and the property under test does not apply.
		t.Skip("POSIX path semantics are asserted on a POSIX host")
	}
	// Asserted on head() rather than on a verdict: a containment rule could
	// mask a naming bug by allowing for an unrelated reason.
	for _, tt := range []struct{ in, want string }{
		{`/usr/bin/rm.`, "rm."},
		{`/usr/bin/rm..`, "rm.."},
		{`/usr/bin/rm `, "rm "},
		{`/usr/bin/rm`, "rm"},
	} {
		if got := head([]string{tt.in}); got != tt.want {
			t.Errorf("head(%q) = %q, want %q: a POSIX file named that is not rm", tt.in, got, tt.want)
		}
	}
	if v := evalSpelling(t, `/usr/bin/rm. -rf /etc`); v.Decision == policy.Deny && v.RuleID == "P1.rm-rf" {
		t.Errorf(`/usr/bin/rm. -rf /etc -> %+v, want no P1.rm-rf`, v)
	}
}

// Operand-keyed families were never affected and must stay that way: they read
// the path operand, not the command name, which is why P4 covered PowerShell
// before #135 existed.
func TestWindowsSpellingDoesNotReachOperandKeyedFamilies(t *testing.T) {
	for _, cmd := range []string{
		`C:\bin\type.exe. C:\Users\u\.ssh\id_ed25519`,
		`Get-Content. C:\Users\u\.ssh\id_ed25519`,
		`totally-unknown-tool. C:\Users\u\.ssh\id_ed25519`,
	} {
		v := evalSpelling(t, cmd)
		if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
			t.Errorf("%q -> %+v, want deny/P4.secret-path", cmd, v)
		}
	}
}

// head() in isolation, so the normalization is pinned independently of any rule.
func TestWindowsHeadNormalizesWin32PathSpellings(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{`rm`, "rm"},
		{`rm.exe`, "rm"},
		{`RM.EXE`, "rm"},
		{`C:\bin\rm.exe`, "rm"},
		{`C:\bin\rm.exe.`, "rm"},
		{`C:\bin\rm.exe..`, "rm"},
		{`C:\bin\rm.exe `, "rm"},
		{`C:\bin\rm.exe. `, "rm"},
		{`C:\bin\rm.`, "rm"},
		{`.\rm.exe.`, "rm"},
		{`C:\bin\rm.exe.exe`, "rm.exe"},
		{`rm.`, "rm."},
		{`rm.exe.exe`, "rm.exe"},
		{`/usr/bin/rm`, "rm"},
	} {
		if got := head([]string{tt.in}); got != tt.want {
			t.Errorf("head(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	// A POSIX-spelled path is the one case whose answer is host-dependent, and
	// correctly so. On a POSIX host `rm.` is a legal, distinct filename and
	// must stay itself. On a Windows host the same spelling reaches Win32
	// through MSYS, which strips the dot, so `rm` is what actually runs.
	wantPosix := "rm."
	if runtime.GOOS == "windows" {
		wantPosix = "rm"
	}
	if got := head([]string{`/usr/bin/rm.`}); got != wantPosix {
		t.Errorf("head(/usr/bin/rm.) = %q, want %q on %s", got, wantPosix, runtime.GOOS)
	}
}
