package adapter

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #498: on Windows Codex runs commands in PowerShell, proven by the session
// transcript (#454). Those commands now get the PowerShell reading #495 gave
// Claude's PowerShell tool: `$true`, `$false` and `$null` are values. A
// transcript naming another shell, or none, keeps the bash reading.

func TestWindowsCodexProvenPowerShellReadsConstantsAsValues(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(repo, "a.txt")
	for _, tc := range []struct {
		shell     string
		command   string
		wantShell string
		allowed   bool
	}{
		{"powershell", `Remove-Item -LiteralPath '` + target + `' -Confirm:$false`, "powershell", true},
		{"pwsh", `Write-Output $true`, "powershell", true},
		{"PowerShell", `git status; $null`, "powershell", true},
		// Unproven: the bash reading, where these are ordinary variables.
		{"bash", `Write-Output $true`, "", false},
		{"", `Write-Output $true`, "", false},
	} {
		call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, repo, tc.shell, tc.command)))
		if err != nil {
			t.Fatalf("%s %q: %v", tc.shell, tc.command, err)
		}
		if call.Shell != tc.wantShell {
			t.Errorf("%s %q: Shell %q, want %q", tc.shell, tc.command, call.Shell, tc.wantShell)
		}
		v := engine.Evaluate(call, pol)
		if got := v.Decision == policy.Allow; got != tc.allowed {
			t.Errorf("%s %q: %s %s; want allowed=%v", tc.shell, tc.command, v.Decision, v.RuleID, tc.allowed)
		}
	}
}

// The proof is read once: the emit step reuses the parsed shell, and an
// allowed command still gets its PowerShell working-directory check.
func TestWindowsCodexEmitReusesTheProvenShell(t *testing.T) {
	repo := t.TempDir()
	call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, repo, "powershell", `Write-Output $true`)))
	if err != nil {
		t.Fatal(err)
	}
	// Remove the transcript: the emit must not need to read it again.
	if err := os.RemoveAll(filepath.Join(os.Getenv("CODEX_HOME"), "sessions")); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := emitCodexAllowedCommand("windows", call, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "Get-Location") || !strings.Contains(out.String(), "Write-Output $true") {
		t.Errorf("updatedInput lacks the precondition or the command: %s", out.String())
	}
}

func TestWindowsCodexReportedPowerShellParseFailures(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	for _, tc := range []struct {
		command string
		want    policy.Decision
	}{
		{"Test-Path -LiteralPath 'skills/council/SKILL.md' -PathType Leaf\n git branch --show-current\n$PSVersionTable.PSVersion.ToString()\n$PSVersionTable.PSEdition\ncodex --version", policy.Ask},
		{"Set-Content -LiteralPath (Join-Path ([System.IO.Path]::GetTempPath()) 'codex-issue-54-report.md') -Encoding utf8 -Value @'\nreport text\n'@", policy.Ask},
		{"Test-Path -LiteralPath 'skills/council/SKILL.md' -PathType Leaf\n git branch --show-current\n codex --version", policy.Allow},
		{"$PSVersionTable.PSVersion.ToString()", policy.Ask},
	} {
		for _, shell := range []string{"powershell", ""} {
			call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, repo, shell, tc.command)))
			if err != nil {
				t.Fatal(err)
			}
			v := engine.Evaluate(call, pol)
			if v.Decision != tc.want || (tc.want == policy.Ask && v.RuleID != "tokenize-failed") {
				t.Errorf("shell %q, command %q: got %s %s (%s), want %s", shell, tc.command, v.Decision, v.RuleID, v.Reason, tc.want)
			} else {
				t.Logf("shell %q, command %q: %s %s (%s)", shell, tc.command, v.Decision, v.RuleID, v.Reason)
			}
		}
	}
}

func TestWindowsCodexStandalonePowerShellProbes(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	for _, tc := range []struct {
		command string
		rule    string
	}{
		{"$PSVersionTable.PSVersion", ""},
		{"$PSVersionTable.PSEdition", ""},
		{"(Get-Command git).Source", ""},
		{"$PSVersionTable.PSVersion; $PSVersionTable.PSEdition; (Get-Command git).Source", ""},
		{"(Get-Command $program).Source", "tokenize-failed"},
		{"$program", "P3.unresolved"},
		{"Test-Path -LiteralPath $PSVersionTable.PSEdition", "P3.unresolved"},
		{"$PSVersionTable.PSEdition > $target", "P3.unresolved"},
		{"@'\nIt's a report with " + string(rune(96)) + "code" + string(rune(96)) + ".\n'@ | Set-Content -LiteralPath '" + filepath.Join(repo, "report.md") + "' -Encoding utf8", "tokenize-failed"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, repo, "pwsh", tc.command)))
			if err != nil {
				t.Fatal(err)
			}
			v := engine.Evaluate(call, pol)
			var out, stderr bytes.Buffer
			code := EmitCodex(v, "pre", call, &out, &stderr)
			if tc.rule == "" {
				if v.Decision != policy.Allow || code != 0 || !strings.HasSuffix(updatedCommand(t, out.String()), "\n"+tc.command) {
					t.Fatalf("decision=%+v code=%d stderr=%q", v, code, stderr.String())
				}
				return
			}
			if v.Decision != policy.Ask || v.RuleID != tc.rule || !strings.Contains(stderr.String(), tc.rule) ||
				!strings.Contains(stderr.String(), "cannot request approval") {
				t.Fatalf("decision=%+v stderr=%q, want %s and guidance", v, stderr.String(), tc.rule)
			}
		})
	}
}

func TestWindowsCodexLiteralGitBashCallOperator(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command string
		allowed bool
	}{
		{`& 'C:\Program Files\Git\bin\bash.exe' --version`, true},
		{`& 'C:\Program Files\Git\bin\bash.exe' -c 'echo $BASH_VERSION; uname -s'`, true},
		{`& 'C:/Program Files/Git/bin/bash.exe' -c 'echo ''hello world'''`, true},
		{`& 'C:/Program Files/Git/bin/bash.exe' -c 'cat ''./.env'''`, false},
		{`& 'C:/Program Files/Git/bin/bash.exe' -c 'echo ok'; Get-Content .env`, false},
		{`& 'C:/Program Files/Git/bin/bash.exe' -c $command`, false},
		{`& 'C:/Program Files/Git/bin/bash.exe' -c 'echo ’hello’'`, false},
		{`& 'C:/Windows/System32/bash.exe' -c 'echo ok'`, false},
	} {
		t.Run(test.command, func(t *testing.T) {
			call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, repo, "pwsh", test.command)))
			if err != nil {
				t.Fatal(err)
			}
			v := engine.Evaluate(call, pol)
			if (v.Decision == policy.Allow) != test.allowed {
				t.Fatalf("decision=%+v, want allow=%t", v, test.allowed)
			}
			if test.allowed {
				var out, stderr bytes.Buffer
				if code := EmitCodex(v, "pre", call, &out, &stderr); code != 0 ||
					!strings.HasSuffix(updatedCommand(t, out.String()), "\n"+test.command) {
					t.Fatalf("code=%d, stdout=%q, stderr=%q", code, out.String(), stderr.String())
				}
			}
		})
	}
}
