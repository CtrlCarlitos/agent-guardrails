package engine

import (
	"runtime"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// outsideRepoTarget is an absolute path outside the repo on the running host.
// Containment is host-owned (see TestWindowsRepoFileContainmentFollowsTheHost):
// `C:\…` is absolute only on Windows and `/etc` only on POSIX, so a test that
// wants "outside the repo" has to ask the host what that spells.
func outsideRepoTarget() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32`
	}
	return "/etc"
}

func repoRootForHost() string {
	if runtime.GOOS == "windows" {
		return `C:\repo`
	}
	return "/repo"
}

func evalPowerShell(t *testing.T, cmd string) *policy.Verdict {
	t.Helper()
	root := repoRootForHost()
	pol := bashPol()
	return checkBash(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "PowerShell",
		Command: cmd, CWD: root, RepoRoot: root}, pol)
}

// A PowerShell tool reaches the Engine through the same command capability as
// bash — the Claude contract maps it onto the Bash analyser — so the P1
// destructive family must recognise the cmdlet that deletes a tree, not only
// the POSIX command that does. Measured before this rule existed: every form
// below allowed.
func TestWindowsPowerShellRemoveItemRecursiveForceDenies(t *testing.T) {
	target := outsideRepoTarget()
	for _, cmd := range []string{
		`Remove-Item -Recurse -Force ` + target,
		`Remove-Item -Path ` + target + ` -Recurse -Force`,
		`Remove-Item ` + target + ` -Recurse`,
		`Remove-Item -Force ` + target,
		`Remove-Item -LiteralPath ` + target + ` -Recurse -Force`,
		// Aliases resolve to Remove-Item only alongside a cmdlet parameter.
		`ri -Recurse -Force ` + target,
		`rd -Recurse -Force ` + target,
		`del -Recurse -Force ` + target,
		`erase -Recurse -Force ` + target,
		`rmdir -Recurse -Force ` + target,
		// PowerShell binds any unambiguous parameter prefix.
		`Remove-Item -rec -fo ` + target,
		`Remove-Item -R -F ` + target,
		// Case is not significant to a cmdlet name or a parameter.
		`REMOVE-ITEM -RECURSE -FORCE ` + target,
		// Separators and pipelines do not hide the operand.
		`Get-Date; Remove-Item -Recurse -Force ` + target,
		// Win32 trailing-dot spelling of the cmdlet name.
		`Remove-Item. -Recurse -Force ` + target,
	} {
		v := evalPowerShell(t, cmd)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
			t.Errorf("%q -> %+v, want deny/P1.rm-rf", cmd, v)
		}
	}
}

// The projection is a mapping onto the POSIX rule, not a second rule set: the
// cmdlet and the command it stands for must reach the same verdict for the
// same operand on the same host. This is the property that keeps the two
// spellings from drifting apart.
func TestWindowsPowerShellRemoveItemMatchesRmVerdict(t *testing.T) {
	root := repoRootForHost()
	for _, tt := range []struct{ powershell, bash string }{
		{`Remove-Item -Recurse -Force ` + outsideRepoTarget(), `rm -rf ` + outsideRepoTarget()},
		{`Remove-Item -Recurse -Force ` + root, `rm -rf ` + root},
		{`Remove-Item -Recurse -Force ` + root + `/sub`, `rm -rf ` + root + `/sub`},
	} {
		got := evalPowerShell(t, tt.powershell)
		want := evalPowerShell(t, tt.bash)
		if decisionOf(got) != decisionOf(want) || ruleOf(got) != ruleOf(want) {
			t.Errorf("%q -> %+v, but %q -> %+v; the projection must agree with the command it maps to",
				tt.powershell, got, tt.bash, want)
		}
	}
}

// -WhatIf is PowerShell's dry run. It prints what would be removed and removes
// nothing, so it must not deny — the same exemption `git clean --dry-run`
// already gets.
func TestWindowsPowerShellRemoveItemWhatIfIsNotDestructive(t *testing.T) {
	for _, cmd := range []string{
		`Remove-Item -Recurse -Force ` + outsideRepoTarget() + ` -WhatIf`,
		`Remove-Item -WhatIf -Recurse -Force ` + outsideRepoTarget(),
	} {
		if v := evalPowerShell(t, cmd); v != nil && v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want no deny (dry run removes nothing)", cmd, v)
		}
	}
}

// Value-taking parameters must not leak their argument into the operand list:
// a filter or a stream name is not a path to delete, and treating one as a
// path would deny commands that are in fact confined to the repo.
func TestWindowsPowerShellRemoveItemParameterValuesAreNotOperands(t *testing.T) {
	root := repoRootForHost()
	for _, cmd := range []string{
		`Remove-Item -Recurse -Force -Filter ` + outsideRepoTarget() + ` ` + root,
		`Remove-Item -Recurse -Force -Exclude ` + outsideRepoTarget() + ` ` + root,
		`Remove-Item -Recurse -Force -Stream ` + outsideRepoTarget() + ` ` + root,
	} {
		if v := evalPowerShell(t, cmd); v != nil && v.Decision == policy.Deny {
			t.Errorf("%q -> %+v, want no deny (the outside path is a parameter value, not an operand)", cmd, v)
		}
	}
}

// The POSIX commands that share a name with a Remove-Item alias keep their own
// semantics. `rmdir /tmp/x` removes one empty directory and `del` is not a
// command at all on POSIX; neither becomes a recursive delete because the
// cmdlet has an alias by that name.
func TestWindowsPowerShellAliasesDoNotCapturePosixCommands(t *testing.T) {
	for _, cmd := range []string{
		`rmdir ` + outsideRepoTarget(),
		`rmdir -p ` + outsideRepoTarget(),
	} {
		if v := evalPowerShell(t, cmd); v != nil && v.RuleID == "P1.rm-rf" {
			t.Errorf("%q -> %+v, want no P1.rm-rf (POSIX rmdir is not a recursive delete)", cmd, v)
		}
	}
}

// Volume and partition cmdlets destroy a filesystem the way mkfs does, and
// they take no path operand that any other family would see.
func TestWindowsPowerShellDiskDestroyersDeny(t *testing.T) {
	for _, cmd := range []string{
		`Format-Volume -DriveLetter C`,
		`Format-Volume. -DriveLetter C`,
		`Clear-Disk -Number 0 -RemoveData`,
		`Remove-Partition -DiskNumber 0 -PartitionNumber 1`,
		`Initialize-Disk -Number 0`,
		`format-volume -DriveLetter C`,
	} {
		v := evalPowerShell(t, cmd)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.mkfs" {
			t.Errorf("%q -> %+v, want deny/P1.mkfs", cmd, v)
		}
	}
}

// Set-ExecutionPolicy Bypass turns off script-signing enforcement for the
// host. It widens what may run the way chmod 777 widens what may be written,
// and gets the same ask.
func TestWindowsPowerShellExecutionPolicyWideningAsks(t *testing.T) {
	for _, cmd := range []string{
		`Set-ExecutionPolicy Bypass`,
		`Set-ExecutionPolicy Unrestricted -Scope CurrentUser`,
		`Set-ExecutionPolicy -ExecutionPolicy Bypass -Force`,
		`set-executionpolicy bypass`,
	} {
		v := evalPowerShell(t, cmd)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P1.execution-policy" {
			t.Errorf("%q -> %+v, want ask/P1.execution-policy", cmd, v)
		}
	}
	// Restricted and AllSigned narrow rather than widen; they are not the risk.
	for _, cmd := range []string{
		`Set-ExecutionPolicy Restricted`,
		`Set-ExecutionPolicy AllSigned`,
	} {
		if v := evalPowerShell(t, cmd); v != nil && v.RuleID == "P1.execution-policy" {
			t.Errorf("%q -> %+v, want no ask (narrowing the policy is not widening it)", cmd, v)
		}
	}
}

// Every rule here is keyed on the cmdlet name, not on the host or the plane: a
// bash tool can spawn `powershell -Command`, and a plane can mislabel its own
// tool. The verdict must not depend on either.
func TestWindowsPowerShellRulesApplyRegardlessOfNativeTool(t *testing.T) {
	root := repoRootForHost()
	cmd := `Remove-Item -Recurse -Force ` + outsideRepoTarget()
	for _, native := range []string{"", "Bash", "PowerShell", "shell"} {
		v := checkBash(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: native,
			Command: cmd, CWD: root, RepoRoot: root}, bashPol())
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
			t.Errorf("native tool %q: %q -> %+v, want deny/P1.rm-rf", native, cmd, v)
		}
	}
}

func decisionOf(v *policy.Verdict) policy.Decision {
	if v == nil {
		return policy.Allow
	}
	return v.Decision
}

func ruleOf(v *policy.Verdict) string {
	if v == nil {
		return ""
	}
	return v.RuleID
}
