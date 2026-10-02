package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #404: residual ways to reach the installed guardrail binary after #146,
// measured on main (v0.23.32-dev) before fixing:
//   deno eval / bun -e naming the binary ............ allow
//   powershell/pwsh -EncodedCommand ................. allow (opaque code)
//   Remove-Item / rm -d / rmdir of ~/.local/bin ..... allow / allow / ask
//   GOBIN=<install dir> go install ./cmd/guardrail .. ask (P1.out-of-repo-write)
// Each now refuses or asks. Runtime-built paths inside interpreter code and
// script files stay outside static analysis (ADR-0033 "unseen execution
// path").

func evalResidual(t *testing.T, native, cmd string) policy.Verdict {
	t.Helper()
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	return Evaluate(ToolCall{Plane: "claude", Event: "pre", Tool: "Bash", NativeTool: native, Capability: policy.CapabilityCommand, InputShape: "command", Command: cmd, CWD: repo, RepoRoot: repo}, pol)
}

func installDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(filepath.Join(home, ".local", "bin"))
}

func TestDenoAndBunNamingTheBinaryAreRefused(t *testing.T) {
	bin := installDir(t) + "/guardrail"
	for _, cmd := range []string{
		`deno eval "Deno.writeFileSync('` + bin + `', new Uint8Array())"`,
		`deno run -A -e "Deno.removeSync('` + bin + `.exe')"`,
		`bun -e "require('fs').writeFileSync('` + bin + `','')"`,
		`bun --eval "require('fs').unlinkSync('` + bin + `.exe')"`,
	} {
		if v := evalResidual(t, "Bash", cmd); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%s: %s %s; want deny P5.self-config", cmd, v.Decision, v.RuleID)
		}
	}
	// Code that names no guardrail path is unaffected.
	if v := evalResidual(t, "Bash", `deno eval "console.log(1)"`); v.RuleID == "P5.self-config" {
		t.Errorf("deno eval of unrelated code: %s %s", v.Decision, v.RuleID)
	}
}

func TestEncodedPowerShellCommandsAsk(t *testing.T) {
	for _, c := range []struct{ native, cmd string }{
		{"PowerShell", `powershell -EncodedCommand SQBuAHYAbwBrAGUA`},
		{"Bash", `pwsh -enc SQBuAHYAbwBrAGUA`},
		{"Bash", `pwsh.exe -NoProfile -e SQBuAHYAbwBrAGUA`},
		{"Bash", `powershell.exe -ec SQBuAHYAbwBrAGUA`},
		{"PowerShell", `pwsh -NonInteractive -EncodedCommand SQBuAHYAbwBrAGUA`},
	} {
		v := evalResidual(t, c.native, c.cmd)
		if v.Decision == policy.Allow {
			t.Errorf("%s %s: allowed; want an ask or deny for opaque encoded code", c.native, c.cmd)
		}
	}
	// -ExecutionPolicy is not an encoded command.
	if v := evalResidual(t, "Bash", `pwsh -ExecutionPolicy Bypass -NoProfile -Command "Get-Date"`); v.RuleID == "P6.dynamic-eval" {
		t.Errorf("-ExecutionPolicy read as -EncodedCommand: %s %s", v.Decision, v.RuleID)
	}
}

func TestDeletingTheInstallDirectoryIsRefused(t *testing.T) {
	dir := installDir(t)
	win := strings.ReplaceAll(dir, "/", `\`)
	for _, c := range []struct{ native, cmd string }{
		{"Bash", `rmdir ` + dir},
		{"Bash", `rm -d ` + dir},
		{"Bash", `rmdir ~/.local/bin`},
		{"PowerShell", `Remove-Item ` + win},
		{"PowerShell", `Remove-Item -LiteralPath '` + win + `\'`},
		{"PowerShell", `rd ` + win},
	} {
		if v := evalResidual(t, c.native, c.cmd); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%s %s: %s %s; want deny P5.self-config", c.native, c.cmd, v.Decision, v.RuleID)
		}
	}
	// A repository's own bin directory is not the install location.
	if v := evalResidual(t, "Bash", `rmdir bin`); v.RuleID == "P5.self-config" {
		t.Errorf("rmdir bin (repo build output): %s %s", v.Decision, v.RuleID)
	}
}

func TestGoInstallingGuardrailOverTheBinaryIsRefused(t *testing.T) {
	dir := installDir(t)
	for _, cmd := range []string{
		`GOBIN=` + dir + ` go install ./cmd/guardrail`,
		`GOBIN=~/.local/bin go install ./cmd/guardrail`,
		`GOBIN=` + dir + ` go install github.com/CtrlCarlitos/agent-guardrails/cmd/guardrail@latest`,
		`env GOBIN=` + dir + ` go install ./cmd/guardrail`,
	} {
		if v := evalResidual(t, "Bash", cmd); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%s: %s %s; want deny P5.self-config", cmd, v.Decision, v.RuleID)
		}
	}
	// Elsewhere, or another tool, keeps its old verdict (not P5).
	for _, cmd := range []string{`go install ./cmd/guardrail`, `GOBIN=` + dir + ` go install golang.org/x/tools/cmd/goimports@latest`} {
		if v := evalResidual(t, "Bash", cmd); v.RuleID == "P5.self-config" {
			t.Errorf("%s: %s %s; want it judged as before", cmd, v.Decision, v.RuleID)
		}
	}
}
