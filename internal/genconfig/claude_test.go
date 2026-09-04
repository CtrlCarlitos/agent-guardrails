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

func TestClaudeConfigShape(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	deny := perms["deny"].([]string)
	if !slices.Contains(deny, "Bash(rm -rf *)") || !slices.Contains(deny, "Read(**/.ssh/**)") {
		t.Errorf("deny incomplete: %v", deny)
	}
	if _, ok := frag["hooks"]; !ok {
		t.Error("hooks missing")
	}
	ask := perms["ask"].([]string)
	if !slices.Contains(ask, "Bash(chmod -R *)") {
		t.Errorf("ask incomplete: %v", ask)
	}
}

func TestBashDenyGlobsP2P6(t *testing.T) {
	got := bashDenyGlobs()
	for _, m := range []string{"Bash(git reset --hard*)", "Bash(git config *)", "Bash(pip install --index-url*)"} {
		if !slices.Contains(got, m) {
			t.Errorf("missing %q", m)
		}
	}
}

func TestBashAskGlobsP2P6(t *testing.T) {
	got := bashAskGlobs()
	for _, m := range []string{"Bash(git checkout .)", "Bash(git branch -D *)", "Bash(pip install *)", "Bash(git push * main)"} {
		if !slices.Contains(got, m) {
			t.Errorf("missing %q", m)
		}
	}
}

func TestSelfConfigAndGitProtectedDenyGlobs(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	deny := frag["permissions"].(map[string]any)["deny"].([]string)
	for _, m := range []string{"Edit(.claude/**)", "Edit(CLAUDE.md)", "Edit(**/.git/config)", "Edit(**/.git/hooks/**)"} {
		if !slices.Contains(deny, m) {
			t.Errorf("deny missing %q: %v", m, deny)
		}
	}
	ask := frag["permissions"].(map[string]any)["ask"].([]string)
	for _, m := range []string{"Edit(.github/workflows/**)", "Edit(go.sum)"} {
		if !slices.Contains(ask, m) {
			t.Errorf("ask missing %q: %v", m, ask)
		}
	}
}

func TestClaudeConfigProtectsGuardrailOwnMachinery(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	deny := frag["permissions"].(map[string]any)["deny"].([]string)
	want := []string{
		"Edit(guardrail.toml)",
		"Edit(**/guardrail.toml)",
		"Edit(.guardrail/**)",
		"Edit(opencode.json)",
		"Edit(**/opencode.json)",
		"Edit(.agents/hooks.json)",
		"Edit(**/.gemini/config/hooks.json)",
		"Edit(**/.local/bin/guardrail)",
		"Edit(**/bin/guardrail)",
	}
	for _, entry := range want {
		if !slices.Contains(deny, entry) {
			t.Errorf("Claude deny missing %q: %v", entry, deny)
		}
	}
}

func TestClaudeHooks(t *testing.T) {
	h := claudeHooks("/usr/local/bin/guardrail")
	pre := h["PreToolUse"].([]any)[0].(map[string]any)
	if pre["id"] != "guardrail-claude-pre" {
		t.Errorf("pre id = %v, want guardrail-claude-pre", pre["id"])
	}
	if pre["matcher"].(string) != "Bash|Read|Edit|Write|MultiEdit" {
		t.Errorf("matcher = %v", pre["matcher"])
	}
	hk := pre["hooks"].([]any)[0].(map[string]any)
	if hk["command"].(string) != "/usr/local/bin/guardrail hook claude" {
		t.Errorf("command = %v", hk["command"])
	}
	post := h["PostToolUse"].([]any)[0].(map[string]any)
	if post["id"] != "guardrail-claude-post" {
		t.Errorf("post id = %v", post["id"])
	}
}

func TestClaudeHooksSessionStart(t *testing.T) {
	h := claudeHooks("/usr/local/bin/guardrail")
	ss, ok := h["SessionStart"].([]any)
	if !ok || len(ss) != 1 {
		t.Fatalf("SessionStart shape wrong: %#v", h["SessionStart"])
	}
	g := ss[0].(map[string]any)
	if g["id"] != "guardrail-claude-session-start" {
		t.Errorf("id = %v", g["id"])
	}
	cmd := g["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if cmd != "/usr/local/bin/guardrail hook claude" {
		t.Errorf("command = %q", cmd)
	}
}
