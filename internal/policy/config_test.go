package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func gitInit(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.email", "t@t"}, {"config", "user.name", "t"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestFindOverlayPathGitRoot(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "guardrail.toml")
	if err := os.WriteFile(cfg, []byte("engine_min_version = \"0.1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := FindOverlayPath(sub)
	if !ok || got != cfg {
		t.Fatalf("FindOverlayPath(%q) = %q,%v; want %q,true", sub, got, ok, cfg)
	}
}

func TestFindOverlayPathEnvOverride(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "/tmp/custom.toml")
	got, ok := FindOverlayPath("/anywhere")
	if !ok || got != "/tmp/custom.toml" {
		t.Fatalf("got %q,%v", got, ok)
	}
}

func TestFindOverlayPathNone(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "")
	dir := t.TempDir() // not a git repo
	if got, ok := FindOverlayPath(dir); ok {
		t.Fatalf("want no overlay, got %q", got)
	}
}

func TestLoadOverlay(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guardrail.toml")
	os.WriteFile(p, []byte(`
engine_min_version = "1.2"
audit_log = ".agents/guardrail.jsonl"

[slots]
safe_roots = ["./tmp"]
egress_allowlist = ["api.example.com"]

[[rules]]
id = "proj.tf"
pattern = "terraform apply*"
decision = "ask"
reason = "infra change"

waive = ["P6.curl-egress"]
`), 0o644)
	ov, err := LoadOverlay(p)
	if err != nil {
		t.Fatal(err)
	}
	if ov.EngineMinVersion != "1.2" || ov.AuditLog != ".agents/guardrail.jsonl" {
		t.Errorf("scalars wrong: %+v", ov)
	}
	if len(ov.SafeRoots) != 1 || ov.SafeRoots[0] != "./tmp" {
		t.Errorf("safe_roots wrong: %v", ov.SafeRoots)
	}
	if len(ov.Rules) != 1 || ov.Rules[0].Decision != Ask {
		t.Errorf("rules wrong: %+v", ov.Rules)
	}
	if len(ov.Waive) != 1 || ov.Waive[0] != "P6.curl-egress" {
		t.Errorf("waive wrong: %v", ov.Waive)
	}
}
