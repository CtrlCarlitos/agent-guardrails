package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #495: in PowerShell `$true`, `$false` and `$null` are constants; assigning
// one is an error ("cannot overwrite variable true because it is read-only or
// constant"). The Engine reads PowerShell with a POSIX parser and asked
// P3.unresolved on every one: `Remove-Item … -Confirm:$false`, `Write-Output
// $true`, `git status; $null`. For Claude's PowerShell tool they are values.
// A switch's `$true`/`$false` inline argument is not a path operand either.
// In bash the same words name ordinary variables, so nothing changes there.

func evalPSTool(t *testing.T, cmd, repo string) policy.Verdict {
	t.Helper()
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	return Evaluate(ToolCall{Plane: "claude", Event: "pre", Tool: "Bash", NativeTool: "PowerShell", Capability: policy.CapabilityCommand, InputShape: "command", Command: cmd, CWD: repo, RepoRoot: repo}, pol)
}

func psRepo(t *testing.T) (repo, inside string) {
	t.Helper()
	repo = t.TempDir()
	inside = filepath.Join(repo, ".worktrees", "done")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	return repo, inside
}

func TestPowerShellConstantsAreValues(t *testing.T) {
	repo, inside := psRepo(t)
	for _, cmd := range []string{
		// The operator's prompt, shape for shape.
		`Remove-Item -Recurse -Force -LiteralPath '` + inside + `' -Confirm:$false; Get-ChildItem -Force -LiteralPath '` + repo + `' | Measure-Object | Select-Object -ExpandProperty Count`,
		`Remove-Item -LiteralPath '` + filepath.Join(inside, "a.txt") + `' -Confirm:$false`,
		`Write-Output $true`,
		`Write-Output $FALSE`,
		`git status; $null`,
		`Get-ChildItem -Force:$true`,
	} {
		if v := evalPSTool(t, cmd, repo); v.Decision != policy.Allow {
			t.Errorf("%s: %s %s (%s); want allow", cmd, v.Decision, v.RuleID, v.Reason)
		}
	}
}

func TestPowerShellConstantsKeepEveryDeny(t *testing.T) {
	repo, _ := psRepo(t)
	// Not under the temp root: that is a configured safe root, where a
	// recursive delete is allowed whatever the dialect.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(home, "guardrail-495-not-a-safe-root")
	for _, cmd := range []string{
		`Remove-Item -Recurse:$true -Force:$true -LiteralPath '` + repo + `'`,
		`Remove-Item -LiteralPath '` + repo + `' -Recurse:$true -Force -Confirm:$false`,
		`Remove-Item -Recurse:$false -Force -LiteralPath '` + repo + `'`,
		`Remove-Item -Recurse -Force -LiteralPath '` + outside + `' -Confirm:$false`,
	} {
		if v := evalPSTool(t, cmd, repo); v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
			t.Errorf("%s: %s %s; want deny P1.rm-rf", cmd, v.Decision, v.RuleID)
		}
	}
}

func TestOnlyTheExactConstantsAreValues(t *testing.T) {
	repo, _ := psRepo(t)
	for _, cmd := range []string{
		`Get-Content $truex`,
		`Get-Content "$true/x"`,
		`Get-Content $true.Path`,
		`Remove-Item -LiteralPath $target -Confirm:$false`,
		`Get-Content -Path:$x`,
	} {
		if v := evalPSTool(t, cmd, repo); v.Decision == policy.Allow {
			t.Errorf("%s: allowed; want it held", cmd)
		}
	}
}

// Bash has no such constants: `false` is a variable name like any other.
func TestBashKeepsTrueFalseNullUnresolved(t *testing.T) {
	repo, _ := psRepo(t)
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		`false=$(pwd); rm -rf $false`,
		`cat $true`,
		`echo hi > $false`,
	} {
		v := Evaluate(ToolCall{Plane: "claude", Event: "pre", Tool: "Bash", NativeTool: "Bash", Capability: policy.CapabilityCommand, InputShape: "command", Command: cmd, CWD: repo, RepoRoot: repo}, pol)
		if v.Decision == policy.Allow {
			t.Errorf("bash %s: allowed; want it held", cmd)
		}
	}
}
