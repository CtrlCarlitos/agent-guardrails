package genconfig

import (
	"slices"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestBashDenyGlobs(t *testing.T) {
	got := bashDenyGlobs()
	mustHave := []string{
		"Bash(rm -rf *)", "Bash(dd *)", "Bash(mkfs*)", "Bash(shred *)",
		"Bash(sudo *)", "Bash(git push --force*)", "Bash(git clean -f*)",
		"Bash(docker compose down*)", "Bash(docker system prune*)",
	}
	for _, m := range mustHave {
		if !slices.Contains(got, m) {
			t.Errorf("bashDenyGlobs missing %q; got %v", m, got)
		}
	}
	for _, g := range got {
		if !strings.HasPrefix(g, "Bash(") || !strings.HasSuffix(g, ")") {
			t.Errorf("malformed glob %q", g)
		}
	}
}

func TestBashAskGlobs(t *testing.T) {
	got := bashAskGlobs()
	for _, m := range []string{"Bash(chmod -R *)", "Bash(chown -R *)", "Bash(truncate *)", "Bash(pkill *)"} {
		if !slices.Contains(got, m) {
			t.Errorf("bashAskGlobs missing %q", m)
		}
	}
}

func secretPol() *policy.Policy {
	return &policy.Policy{Slots: policy.Slots{
		SecretGlobs: []string{"**/.env", ".env.*", "**/.ssh/**", "id_rsa*", "*.pem"},
		SecretAllow: []string{"**/.env.example", ".env.example"},
	}}
}

func TestSecretDenyGlobs(t *testing.T) {
	got := secretDenyGlobs(secretPol())
	want := []string{
		"Read(**/.env)", "Read(**/.ssh/**)", "Read(id_rsa*)", "Read(*.pem)",
		"Edit(**/.env)", "Edit(**/.ssh/**)", "Edit(id_rsa*)", "Edit(*.pem)",
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
	// .env.* collides with .env.example -> must be dropped entirely.
	for _, bad := range []string{"Read(.env.*)", "Edit(.env.*)"} {
		if slices.Contains(got, bad) {
			t.Errorf("%q should have been dropped (collides with secret_allow)", bad)
		}
	}
}

func TestClaudeHooks(t *testing.T) {
	h := claudeHooks("/usr/local/bin/guardrail")
	pre, ok := h["PreToolUse"].([]any)
	if !ok || len(pre) != 1 {
		t.Fatalf("PreToolUse shape wrong: %#v", h["PreToolUse"])
	}
	entry := pre[0].(map[string]any)
	if entry["matcher"].(string) != "Bash|Read|Edit|Write|MultiEdit" {
		t.Errorf("matcher = %v", entry["matcher"])
	}
	hk := entry["hooks"].([]any)[0].(map[string]any)
	if hk["command"].(string) != "/usr/local/bin/guardrail hook claude" {
		t.Errorf("command = %v", hk["command"])
	}
	if _, ok := h["PostToolUse"]; !ok {
		t.Error("PostToolUse missing")
	}
}
