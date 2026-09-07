package genconfig

import (
	"slices"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

func TestBashDenyGlobs(t *testing.T) {
	got := bashDenyGlobs()
	mustHave := []string{
		"Bash(rm -rf /)", "Bash(dd *)", "Bash(mkfs*)", "Bash(shred *)",
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
		SecretDirs:     []string{"**/.ssh/**"},
		SecretGlobs:    []string{"**/.env", ".env.*", "id_rsa*"},
		SecretAskGlobs: []string{"**/*.pem"},
		SecretAllow:    []string{"**/.env.example", ".env.example"},
	}}
}

// Claude resolves matching permissions by tier, regardless of list order:
// deny first, then ask, then allow.
func claudeNativeDecision(perms map[string]any, operation string) string {
	operationTool, operationPath, ok := strings.Cut(strings.TrimSuffix(operation, ")"), "(")
	if !ok {
		return ""
	}
	for _, decision := range []string{"deny", "ask", "allow"} {
		entries, _ := perms[decision].([]string)
		for _, entry := range entries {
			entryTool, entryGlob, ok := strings.Cut(strings.TrimSuffix(entry, ")"), "(")
			if ok && entryTool == operationTool {
				matched, _ := doublestar.Match(entryGlob, operationPath)
				if matched {
					return decision
				}
			}
		}
	}
	return ""
}

func TestSecretDirsReachTheDeclarativeFloor(t *testing.T) {
	pol := &policy.Policy{Slots: policy.Slots{
		SecretDirs:  []string{"**/.ssh/**"},
		SecretGlobs: []string{"**/.env"},
		SecretAllow: []string{"**/.ssh/**"},
	}}
	got := secretDenyGlobs(pol)
	for _, want := range []string{"Read(**/.ssh/**)", "Edit(**/.ssh/**)", "Read(**/.env)"} {
		if !slices.Contains(got, want) {
			t.Errorf("floor = %v, want to contain %q", got, want)
		}
	}
}

func TestSecretDenyGlobs(t *testing.T) {
	got := secretDenyGlobs(secretPol())
	want := []string{
		"Read(**/.env)", "Read(**/.ssh/**)", "Read(id_rsa*)",
		"Edit(**/.env)", "Edit(**/.ssh/**)", "Edit(id_rsa*)",
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

func TestAskTierAndScopedClaudeReachTheFloor(t *testing.T) {
	pol := &policy.Policy{Slots: policy.Slots{
		SecretDirs:     []string{"**/.ssh/**"},
		SecretAskGlobs: []string{"**/*.pem"},
	}}
	cfg := ClaudeConfig(pol, "guardrail")
	perms := cfg["permissions"].(map[string]any)
	for _, test := range []struct {
		operation string
		want      string
	}{
		{"Read(repo/docs/cert.pem)", "ask"},
		{"Read(home/u/.ssh/client.pem)", "deny"},
		{"Edit(.claude/skills/client.pem)", "deny"},
		{"Edit(.claude/projects/x/memory/client.pem)", "ask"},
		{"Edit(.claude/projects/x/memory/note.md)", ""},
		{"Edit(.claude/settings.json)", "deny"},
		{"Edit(.claude/settings.local.json)", "deny"},
		{"Edit(.claude/hooks/pre.sh)", "deny"},
		{"Edit(.claude/plugins/p.js)", "deny"},
		{"Edit(.claude/agents/a.md)", "deny"},
		{"Edit(.claude/commands/c.md)", "deny"},
		{"Edit(.claude/CLAUDE.md)", "deny"},
	} {
		if got := claudeNativeDecision(perms, test.operation); got != test.want {
			t.Errorf("Claude permission for %q = %q, want %q", test.operation, got, test.want)
		}
	}
}

func TestClaudeConfigShape(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	deny := perms["deny"].([]string)
	if !slices.Contains(deny, "Bash(rm -rf /)") || !slices.Contains(deny, "Read(**/.ssh/**)") {
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
	for _, m := range []string{
		"Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(rm -rf .)", "Bash(rm -rf ..)",
		"Bash(rm -fr /)", "Bash(rm -fr ~)", "Bash(rm -fr .)", "Bash(rm -fr ..)",
		"Bash(rm -r -f /)", "Bash(rm -r -f ~)", "Bash(rm -r -f .)", "Bash(rm -r -f ..)",
		"Bash(rm -f -r /)", "Bash(rm -f -r ~)", "Bash(rm -f -r .)", "Bash(rm -f -r ..)",
		"Bash(srm *)",
		"Bash(git reset --hard*)", "Bash(git config core.hooksPath /**)", "Bash(pip install --index-url*)",
	} {
		if !slices.Contains(got, m) {
			t.Errorf("missing %q", m)
		}
	}
	for _, broad := range []string{
		"Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(rm -r -f *)", "Bash(rm -f -r *)",
		"Bash(rm -rf /*)", "Bash(rm -fr /*)", "Bash(rm -r -f /*)", "Bash(rm -f -r /*)",
	} {
		if slices.Contains(got, broad) {
			t.Errorf("broad native deny %q prevents Engine authorization", broad)
		}
	}
}

func TestGitConfigNativeFloorOnlyPreemptsDefiniteDangerousWrites(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	for _, operation := range []string{
		"Bash(git config user.email x@y.com)",
		"Bash(git config --global --get user.name)",
	} {
		if got := claudeNativeDecision(perms, operation); got != "" {
			t.Errorf("Claude permission for %q = %q, want Engine classification", operation, got)
		}
	}
	if got := claudeNativeDecision(perms, "Bash(git config core.hooksPath /tmp/evil)"); got != "deny" {
		t.Fatalf("dangerous config write native decision = %q, want deny", got)
	}
	if slices.Contains(perms["deny"].([]string), "Bash(git config *)") {
		t.Fatal("broad git config native deny preempts read and approved-write classification")
	}
}

func TestClaudeTempDeleteReachesExistingBashPreHook(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	if got := claudeNativeDecision(perms, "Bash(rm -rf /)"); got != "deny" {
		t.Fatalf("rm -rf / native decision = %q, want deny", got)
	}
	if got := claudeNativeDecision(perms, "Bash(rm -rf /tmp/work/item)"); got != "" {
		t.Fatalf("temp descendant native decision = %q, want no preemptive permission", got)
	}
	if got := claudeNativeDecision(perms, "Bash(find /tmp/work/item -delete)"); got != "" {
		t.Fatalf("scoped find native decision = %q, want no preemptive permission", got)
	}
	hooks := frag["hooks"].(map[string]any)["PreToolUse"].([]any)
	matcher := hooks[0].(map[string]any)["matcher"].(string)
	if !strings.Contains(matcher, "Bash") {
		t.Fatalf("PreToolUse matcher %q does not deliver Bash calls to the Engine", matcher)
	}
}

func TestBashAskGlobsP2P6(t *testing.T) {
	got := bashAskGlobs()
	for _, m := range []string{"Bash(git checkout .)", "Bash(git branch -D *)", "Bash(pip install *)", "Bash(git push * main)"} {
		if !slices.Contains(got, m) {
			t.Errorf("missing %q", m)
		}
	}
	if slices.Contains(got, "Bash(find * -delete)") {
		t.Fatal("broad native find ask prevents Engine authorization")
	}
}

func TestSelfConfigAndGitProtectedDenyGlobs(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	for _, operation := range []string{"Edit(.claude/settings.json)", "Edit(CLAUDE.md)", "Edit(repo/.git/config)", "Edit(repo/.git/hooks/pre-commit)"} {
		if got := claudeNativeDecision(perms, operation); got != "deny" {
			t.Errorf("Claude permission for %q = %q, want deny", operation, got)
		}
	}
	for _, operation := range []string{"Edit(.github/workflows/ci.yml)", "Edit(go.sum)"} {
		if got := claudeNativeDecision(perms, operation); got != "ask" {
			t.Errorf("Claude permission for %q = %q, want ask", operation, got)
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

func TestClaudeConfigProtectsSessionStore(t *testing.T) {
	perms := ClaudeConfig(secretPol(), "guardrail")["permissions"].(map[string]any)
	for _, operation := range []string{
		"Edit(home/u/.local/state/guardrail/sessions/key.json)",
		"Edit(Users/u/Library/Application Support/guardrail/sessions/key.json)",
		"Edit(//home/u/.local/state/guardrail/sessions/key.json)",
	} {
		if got := claudeNativeDecision(perms, operation); got != "deny" {
			t.Errorf("Claude permission for %q = %q, want deny", operation, got)
		}
	}
	deny := perms["deny"].([]string)
	for _, entry := range []string{
		"Edit(//**/guardrail/sessions/**)",
		`Edit(**\guardrail\sessions\**)`,
		"Bash(rm *guardrail/sessions/*)",
		`Bash(rm *guardrail\sessions\*)`,
	} {
		if !slices.Contains(deny, entry) {
			t.Errorf("Claude deny missing session-store fallback %q", entry)
		}
	}
}

func TestClaudeConfigProtectsOperatorConfig(t *testing.T) {
	frag := ClaudeConfig(secretPol(), "guardrail")
	deny := frag["permissions"].(map[string]any)["deny"].([]string)
	want := []string{
		"Edit(**/.config/guardrail/**)",
		"Edit(**/guardrail/waivers.toml)",
		"Edit(//**/.config/guardrail/**)",
		"Edit(//**/guardrail/waivers.toml)",
	}
	for _, entry := range want {
		if !slices.Contains(deny, entry) {
			t.Errorf("Claude deny missing %q: %v", entry, deny)
		}
	}

	validAbsolute := want[2:]
	for _, entry := range deny {
		isOperatorAbsolute := strings.HasPrefix(entry, "Edit(//") &&
			(strings.Contains(entry, ".config/guardrail/") || strings.Contains(entry, "guardrail/waivers.toml"))
		if isOperatorAbsolute && !slices.Contains(validAbsolute, entry) {
			t.Errorf("Claude deny contains malformed absolute operator pattern %q", entry)
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
