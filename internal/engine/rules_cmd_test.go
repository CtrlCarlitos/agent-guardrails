package engine

import (
	"runtime"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Containment is host-owned, the same reason rules_powershell_test.go asks the
// host how "outside the repo" is spelled: `C:\…` is absolute only on Windows.
// The cmd switches stay cmd-shaped on every host — they are what the rule
// reads — but the operands have to be paths the running host can resolve.
func cmdSafeRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\repo\tmp`
	}
	return "/repo/tmp"
}

func cmdInRepo(rest string) string {
	if runtime.GOOS == "windows" {
		return `C:\repo\` + rest
	}
	return "/repo/" + rest
}

func cmdSecretOperand() string {
	if runtime.GOOS == "windows" {
		return `C:\Users\u\.ssh\id_ed25519`
	}
	return "/home/u/.ssh/id_ed25519"
}

func cmdPol() *policy.Policy {
	p := pathPol()
	p.Slots.SafeRoots = []string{cmdSafeRoot()}
	return p
}

func evalCmd(t *testing.T, command string) policy.Verdict {
	t.Helper()
	root := repoRootForHost()
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: command, CWD: root, RepoRoot: root}, cmdPol())
}

// cmd.exe is a third shell a Windows plane can submit, and its switches are
// forward-slashed, so `/s` and `/q` tokenise as path operands and P1 never
// sees a recursive delete (#139).
//
// The semantics below were measured on disposable trees, not assumed:
//
//	del /s /q <dir>    -> every file beneath <dir>, recursively
//	rd  /s /q <dir>    -> the whole tree, directory included
//	erase /s /q <dir>  -> same as del
//	DEL /S /Q <dir>    -> switches are case-insensitive
func TestWindowsCmdRecursiveDeleteOutsideRepoDenies(t *testing.T) {
	target := outsideRepoTarget()
	for _, command := range []string{
		`del /s /q ` + target,
		`del /s /q /f ` + target,
		`erase /s /q ` + target,
		`DEL /S /Q ` + target,
		`rd /s /q ` + target,
		`rd /s ` + target,
		`rmdir /s /q ` + target,
		`RD /S /Q ` + target,
		// A path operand before the switches is the same command.
		`del ` + target + ` /s /q`,
	} {
		v := evalCmd(t, command)
		if v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
			t.Errorf("%q -> %+v, want deny/P1.rm-rf", command, v)
		}
	}
}

// Containment is the same decision the POSIX rule makes: inside the repo is
// ordinary work.
func TestWindowsCmdRecursiveDeleteInsideRepoAllows(t *testing.T) {
	for _, command := range []string{
		`del /s /q ` + cmdInRepo("build"),
		`rd /s /q ` + cmdInRepo("build"),
		`rd /s /q ` + cmdInRepo("tmp/scratch"),
	} {
		if v := evalCmd(t, command); v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want no deny inside the repo", command, v)
		}
	}
}

// Measured: `rd <dir>` without /s fails on a non-empty directory (exit 145),
// so it is not a recursive delete and must not be judged as one. It keeps the
// same ask `rmdir` already gets, since the two names are the same command.
func TestWindowsCmdNonRecursiveRemoveKeepsTheRmdirAsk(t *testing.T) {
	target := outsideRepoTarget()
	for _, command := range []string{
		`rd ` + target,
		`rmdir ` + target,
	} {
		v := evalCmd(t, command)
		if v.Decision != policy.Ask || v.RuleID != "P1.rmdir" {
			t.Errorf("%q -> %+v, want ask/P1.rmdir", command, v)
		}
	}
}

// `cmd /c "<command>"` is an interpreter invocation. The POSIX shells are
// already unwrapped — `sh -c "rm -rf X"` denies — and cmd was not, so the
// wrapper laundered every verdict.
func TestWindowsCmdSlashCUnwrapsTheInnerCommand(t *testing.T) {
	target := outsideRepoTarget()
	for _, command := range []string{
		`cmd /c "rd /s /q ` + target + `"`,
		`cmd.exe /c "del /s /q ` + target + `"`,
		`cmd /C "rd /s /q ` + target + `"`,
		`cmd /c "rm -rf ` + target + `"`,
		`cmd.exe /k "rd /s /q ` + target + `"`,
	} {
		if v := evalCmd(t, command); v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want a deny from the inner command", command, v)
		}
	}
}

// Volume and partition tools destroy a filesystem the way mkfs does.
func TestWindowsCmdDiskDestroyersDeny(t *testing.T) {
	for _, command := range []string{
		`format C: /q`,
		`format /q C:`,
		`FORMAT C: /FS:NTFS`,
		`diskpart /s script.txt`,
	} {
		v := evalCmd(t, command)
		if v.Decision != policy.Deny || v.RuleID != "P1.mkfs" {
			t.Errorf("%q -> %+v, want deny/P1.mkfs", command, v)
		}
	}
}

// POSIX must not move. A POSIX `rm`, `rmdir` or `format` keeps the verdict it
// had before this rule existed.
func TestWindowsCmdRulesDoNotReachPosixCommands(t *testing.T) {
	// A POSIX tool named `format` — a code formatter, say — is not diskpart.
	if v := evalCmd(t, `format --write src/`); v.RuleID == "P1.mkfs" {
		t.Errorf("format --write -> %+v, want no P1.mkfs: no drive operand, no cmd switch", v)
	}
	// rmdir keeps its existing ask, not a recursive-delete deny.
	if v := evalCmd(t, `rmdir /tmp/x`); v.RuleID != "P1.rmdir" {
		t.Errorf("rmdir /tmp/x -> %+v, want the existing P1.rmdir ask", v)
	}
	// A POSIX rm is untouched by any of this.
	if v := evalCmd(t, `rm -rf `+outsideRepoTarget()); v.RuleID != "P1.rm-rf" {
		t.Errorf("rm -rf -> %+v, want P1.rm-rf", v)
	}
}

// The cmd projection reads `/s` as a switch on every host, because the rule
// cannot know which shell submitted the string. On POSIX `/s` is also a
// perfectly good absolute path, so the shapes where the two readings collide
// must not lose a verdict: consuming the operand as a switch must never leave
// a delete with nothing to judge and no ask.
func TestWindowsCmdSwitchReadingDoesNotDropAPosixVerdict(t *testing.T) {
	for _, command := range []string{
		// Every operand looks like a switch: nothing is left to judge, and
		// the non-recursive ask still has to stand.
		`rmdir /s`,
		`rd /s`,
		`rmdir /s /q`,
	} {
		if v := evalCmd(t, command); v.Decision == policy.Allow {
			t.Errorf("%q -> %+v, want an ask or a deny, not a silent allow", command, v)
		}
	}
}

// Operand-keyed families already covered cmd, for the same reason they covered
// PowerShell before #135: they read the operand, not the command name.
func TestWindowsCmdSecretOperandsStillDeny(t *testing.T) {
	secret := cmdSecretOperand()
	for _, command := range []string{
		`type ` + secret,
		`del /s /q ` + secret,
	} {
		if v := evalCmd(t, command); v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", command, v)
		}
	}
}

// The switch/path collision the enumerated switch set exists to prevent,
// pinned directly so it holds on every host rather than only on the one
// running the suite: a leading slash is a cmd switch only for the names the
// command actually has, and anything else stays an operand to be judged.
func TestCmdSwitchLeavesAPosixAbsolutePathAsAnOperand(t *testing.T) {
	for _, arg := range []string{"/etc", "/var/log", "/s/deeper", "/usr", "/tmp"} {
		if name, ok := cmdSwitch(arg, cmdDeleteSwitches); ok {
			t.Errorf("cmdSwitch(%q) = %q, true; want an operand: a leading slash is a path on POSIX", arg, name)
		}
	}
	for _, arg := range []string{"/s", "/S", "/q", "/Q", "/f"} {
		if _, ok := cmdSwitch(arg, cmdDeleteSwitches); !ok {
			t.Errorf("cmdSwitch(%q) = false; want a recognised cmd switch", arg)
		}
	}
	if name, ok := cmdSwitch("/FS:NTFS", cmdFormatSwitches); !ok || name != "fs" {
		t.Errorf(`cmdSwitch("/FS:NTFS") = %q, %v; want "fs", true`, name, ok)
	}
}
