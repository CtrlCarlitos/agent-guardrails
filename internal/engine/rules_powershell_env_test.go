package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func envPol() *policy.Policy {
	pol := pathPol()
	pol.Slots.SafeRoots = []string{repoRootForHost() + "/tmp"}
	return pol
}

// evalEnv goes through Evaluate rather than checkBash: the secret tier lives in
// the path analysis, so the bash family alone reports the P3 ask and never the
// P4 deny that actually wins on severity. These tests assert the verdict an
// agent receives.
func evalEnv(t *testing.T, cmd string) policy.Verdict {
	t.Helper()
	root := repoRootForHost()
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "PowerShell",
		Capability: policy.CapabilityCommand, Command: cmd, CWD: root, RepoRoot: root}, envPol())
}

// `$env:NAME` is PowerShell's environment reference. The bash tokenizer splits
// it at the wrong place — `$env` is an unset variable and `:NAME\tail` is
// literal — so the whole word reads as unresolved and every read through one
// asks, however ordinary.
//
// The Engine cannot know what NAME expands to and does not try: ADR-0012 rules
// out simulating an environment. What it can know is the literal tail, which is
// what the secret tier matches. So in a read-only position the `$env:` prefix
// alone stops raising P3.unresolved and the path families judge the tail.
func TestWindowsPowerShellEnvPrefixIsResolvedForReads(t *testing.T) {
	for _, cmd := range []string{
		`Get-Content $env:USERPROFILE\notes.txt`,
		`Get-Content -Path $env:USERPROFILE\notes.txt`,
		`Get-ChildItem $env:TEMP`,
		`Select-String -Path $env:APPDATA\x.log -Pattern y`,
		`Get-Item $env:LOCALAPPDATA\guardrail\audit.jsonl`,
		`Test-Path $env:TEMP\marker`,
		`gc $env:USERPROFILE\notes.txt`,
	} {
		if v := evalEnv(t, cmd); v.RuleID == "P3.unresolved" {
			t.Errorf("%q -> %+v, want no P3.unresolved: the only unknown is the $env: prefix and this reads", cmd, v)
		}
	}
}

// The tail is still policy. An `$env:` prefix does not launder a secret path —
// this already held before the change and must keep holding, because it is the
// property that makes resolving the prefix safe at all.
func TestWindowsPowerShellEnvPrefixDoesNotLaunderSecretTails(t *testing.T) {
	for _, cmd := range []string{
		`Get-Content $env:USERPROFILE\.ssh\id_ed25519`,
		`Get-Content -Path $env:USERPROFILE\.ssh\id_ed25519`,
		`Select-String -Path $env:USERPROFILE\.aws\credentials -Pattern key`,
		`Get-Content $env:USERPROFILE\.env`,
		`gc $env:HOME\.ssh\id_rsa`,
	} {
		v := evalEnv(t, cmd)
		if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
			t.Errorf("%q -> %+v, want deny/P4.secret-path", cmd, v)
		}
	}
}

// Writes keep the ask. Containment needs to know which root the path is under,
// and that is exactly the part `$env:NAME` withholds — so a delete or a write
// through one is the case the Engine genuinely cannot decide.
func TestWindowsPowerShellEnvPrefixStaysUnresolvedForWrites(t *testing.T) {
	for _, cmd := range []string{
		`Remove-Item -Recurse -Force $env:USERPROFILE`,
		`Remove-Item -Recurse -Force $env:USERPROFILE\scratch`,
		`Remove-Item -LiteralPath $env:TEMP -Recurse -Force`,
		`Set-Content $env:USERPROFILE\notes.txt "x"`,
		`Out-File -FilePath $env:APPDATA\x.txt`,
		`New-Item -ItemType Directory -Force -Path $env:TEMP\scratch`,
	} {
		v := evalEnv(t, cmd)
		if v.Decision == policy.Allow {
			t.Errorf("%q -> %+v, want a non-allow: a write through an unknown root cannot be contained", cmd, v)
		}
	}
}

// Only the `$env:` prefix is forgiven. A read whose *tail* is also unknown is
// still a path the Engine cannot see, and still asks.
func TestWindowsPowerShellUnknownTailStillAsks(t *testing.T) {
	for _, cmd := range []string{
		`Get-Content $env:USERPROFILE\$name`,
		`Get-Content $somewhere\notes.txt`,
		`Get-Content $env:USERPROFILE\$(Get-Thing)`,
	} {
		v := evalEnv(t, cmd)
		if v.Decision != policy.Ask {
			t.Errorf("%q -> %+v, want an ask: the tail is unreadable, not just the prefix", cmd, v)
		}
	}
}

// codex's probe shapes for -LiteralPath, pinned. These already passed before
// this change — the parameter table binds any unambiguous prefix — and the
// point of the test is that they keep passing, not that they are new.
func TestWindowsPowerShellLiteralPathShapes(t *testing.T) {
	target := outsideRepoTarget()
	for _, tt := range []struct {
		cmd      string
		decision policy.Decision
		rule     string
	}{
		{`Remove-Item -LiteralPath ` + target + ` -Recurse -Force`, policy.Deny, "P1.rm-rf"},
		{`Remove-Item -literalpath ` + target + ` -Recurse -Force`, policy.Deny, "P1.rm-rf"},
		{`Remove-Item -lp ` + target + ` -Recurse -Force`, policy.Deny, "P1.rm-rf"},
		{`Remove-Item -LiteralPath:` + target + ` -Recurse -Force`, policy.Deny, "P1.rm-rf"},
		{`Get-Content -LiteralPath C:\Users\u\.ssh\id_ed25519`, policy.Deny, "P4.secret-path"},
	} {
		v := evalEnv(t, tt.cmd)
		if v.Decision != tt.decision || v.RuleID != tt.rule {
			t.Errorf("%q -> %+v, want %s/%s", tt.cmd, v, tt.decision, tt.rule)
		}
	}
}
