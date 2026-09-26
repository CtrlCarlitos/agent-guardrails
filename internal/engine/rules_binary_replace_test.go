package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #146: `Copy-Item <asset> ~\.local\bin\guardrail.exe -Force` was allowed, so a
// mediated session could replace the enforcement binary (and, on a host that
// excludes that path from AV, run it unscanned). The POSIX `cp x guardrail`
// already denied as P5.self-config; the Windows spelling of the file name and
// the Windows copy/move/content commands were both invisible to that rule.
//
// Measured before the fix (Windows host, this Engine): every row below allowed,
// except the `cp`/`mv`/redirect rows, which asked as P1.out-of-repo-write /
// P1.redirect rather than denying.
func TestWindowsReplacingTheEnforcementBinaryIsSelfConfigDeny(t *testing.T) {
	for _, cmd := range []string{
		`Copy-Item C:\Users\u\Downloads\g.exe C:\Users\u\.local\bin\guardrail.exe -Force`,
		`Copy-Item -Path g.exe -Destination C:\Users\u\.local\bin\guardrail.exe`,
		`Copy-Item -Path g.exe -Dest C:\Users\u\.local\bin\guardrail.exe`,
		`copy-item g.exe C:\Users\u\.local\bin\GUARDRAIL.EXE`,
		`Copy-Item g.exe C:/Users/u/.local/bin/guardrail.exe`,
		`copy g.exe C:\Users\u\.local\bin\guardrail.exe`,
		`copy /y g.exe C:\Users\u\.local\bin\guardrail.exe`,
		`cpi g.exe C:\Users\u\.local\bin\guardrail.exe`,
		`Move-Item g.exe C:\Users\u\.local\bin\guardrail.exe -Force`,
		`move g.exe C:\Users\u\.local\bin\guardrail.exe`,
		`cp g.exe C:\Users\u\.local\bin\guardrail.exe`,
		`mv g.exe C:\Users\u\.local\bin\guardrail.exe`,
		`xcopy g.exe C:\Users\u\.local\bin\guardrail.exe /Y`,
		`xcopy /Y C:\dl\guardrail.exe C:\Users\u\.local\bin\`,
		`robocopy C:\dl C:\Users\u\.local\bin guardrail.exe`,
		`robocopy C:\dl C:\Users\u\.local\bin /MIR`,
		`robocopy C:\dl C:\Users\u\.local\bin *.exe /R:0`,
		`Set-Content -Path C:\Users\u\.local\bin\guardrail.exe -Value x`,
		`Set-Content C:\Users\u\.local\bin\guardrail.exe x`,
		`Add-Content -LiteralPath C:\Users\u\.local\bin\guardrail.exe -Value x`,
		`"x" | Out-File C:\Users\u\.local\bin\guardrail.exe`,
		`Out-File -FilePath C:\Users\u\.local\bin\guardrail.exe -InputObject x`,
		`New-Item -Path C:\Users\u\.local\bin -Name guardrail.exe -Value x -Force`,
		`Rename-Item C:\Users\u\.local\bin\g.exe guardrail.exe`,
		`cat g > C:\Users\u\.local\bin\guardrail.exe`,
		// Moving the binary away disables enforcement as surely as replacing it.
		`Move-Item C:\Users\u\.local\bin\guardrail.exe C:\repo\tmp\g.exe`,
		`Rename-Item C:\Users\u\.local\bin\guardrail.exe -NewName g.old`,
		// Other bin directories the release lands in.
		`Copy-Item g.exe C:\tools\bin\guardrail.exe`,
	} {
		v := evalSpelling(t, cmd)
		if v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", cmd, v)
		}
	}
}

// The same cmdlets protect the other self-config paths they used to miss.
func TestWindowsContentCmdletsOnSelfConfigAreDenied(t *testing.T) {
	for _, cmd := range []string{
		`Set-Content C:\Users\u\.claude\settings.json x`,
		`Copy-Item evil.json C:\Users\u\.claude\settings.json`,
		`"x" | Out-File C:\repo\guardrail.toml`,
	} {
		v := evalSpelling(t, cmd)
		if v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", cmd, v)
		}
	}
}

// The staged-update artifact, the reader direction and look-alike names must
// stay clear of the rule.
func TestWindowsBinaryReplaceRuleLeavesNeighboursAlone(t *testing.T) {
	for _, cmd := range []string{
		`Copy-Item g.exe C:\Users\u\.local\bin\guardrail.exe.old`,
		`Copy-Item g.exe C:\Users\u\.local\bin\guardrail.exe.new`,
		`Copy-Item g.exe C:\Users\u\.local\bin\guardrail-x.exe`,
		`Copy-Item C:\Users\u\.local\bin\guardrail.exe C:\repo\tmp\g.exe`,
		`copy C:\Users\u\.local\bin\guardrail.exe C:\repo\tmp\g.exe`,
		`robocopy C:\Users\u\.local\bin C:\repo\tmp guardrail.exe`,
		`Copy-Item a.txt b.txt`,
		`Set-Content -Path C:\repo\tmp\notes.txt -Value x`,
	} {
		v := evalSpelling(t, cmd)
		if v.RuleID == "P5.self-config" {
			t.Errorf("%q -> %+v, must not be P5.self-config", cmd, v)
		}
	}
}

// The POSIX plane: the `.exe` spelling of the binary (WSL and MSYS reach the
// Windows install through /mnt/c and /c) and the bin directories.
func TestPosixReplacingTheEnforcementBinaryIsSelfConfigDeny(t *testing.T) {
	for _, cmd := range []string{
		"cp g /home/u/.local/bin/guardrail",
		"cp g /home/u/.local/bin/guardrail.exe",
		"cp g /mnt/c/Users/u/.local/bin/guardrail.exe",
		"mv g /c/Users/u/.local/bin/guardrail.exe",
		"install -m755 g /usr/local/bin/guardrail",
		"install -m755 g /usr/local/bin/guardrail.exe",
		"cat g > /home/u/.local/bin/guardrail.exe",
		"tee /home/u/.local/bin/guardrail.exe < g",
		"dd if=g of=/home/u/.local/bin/guardrail",
		"cp g /home/u/bin/GUARDRAIL.EXE",
	} {
		v := evalPosixFull(cmd)
		if v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", cmd, v)
		}
	}
	for _, cmd := range []string{
		"cp /home/u/.local/bin/guardrail /repo/tmp/g",
		"cp g /home/u/.local/bin/guardrail.old",
	} {
		if v := evalPosixFull(cmd); v.RuleID == "P5.self-config" {
			t.Errorf("%q -> %+v, must not be P5.self-config", cmd, v)
		}
	}
}

func evalPosixFull(cmd string) policy.Verdict {
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", Capability: policy.CapabilityCommand,
		Command: cmd, CWD: "/repo", RepoRoot: "/repo"}, spellPol())
}
