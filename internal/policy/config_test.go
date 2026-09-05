package policy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
	os.WriteFile(cfg, []byte("engine_min_version = \"0.1\"\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", "")
	got, ok, warn := FindOverlayPath(sub)
	if !ok || got != cfg || warn != "" {
		t.Fatalf("got %q,%v,%q", got, ok, warn)
	}
}

func TestFindOverlayPathEnvPresent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "custom.toml")
	os.WriteFile(p, []byte("engine_min_version=\"9\"\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", p)
	got, ok, warn := FindOverlayPath("/anywhere")
	if !ok || got != p || warn != "" {
		t.Fatalf("got %q,%v,%q", got, ok, warn)
	}
}

func TestFindOverlayPathEnvStale(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "/definitely/not/here.toml")
	got, ok, warn := FindOverlayPath("/anywhere")
	if ok || got != "" {
		t.Fatalf("stale env should yield no overlay; got %q,%v", got, ok)
	}
	if warn == "" || !strings.Contains(warn, "/definitely/not/here.toml") {
		t.Fatalf("want a warning naming the path; got %q", warn)
	}
}

func TestFindOverlayPathNone(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "")
	dir := t.TempDir()
	if _, ok, warn := FindOverlayPath(dir); ok || warn != "" {
		t.Fatalf("want (_, false, \"\"); ok=%v warn=%q", ok, warn)
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

func TestShippedOverlayExampleLoadsAndMerges(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ov, err := LoadOverlay(filepath.Join(repoRoot, "guardrail.toml.example"))
	if err != nil {
		t.Fatalf("shipped Overlay example must load: %v", err)
	}
	base, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	op := &OperatorConfig{Repos: map[string]RepoGrant{
		repoRoot: {EgressAllowlist: []string{"api.github.com"}},
	}}

	merged, warns, err := Merge(base, ov, "1.0.0", op, repoRoot)
	if err != nil {
		t.Fatalf("shipped Overlay example must merge: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("shipped Overlay example produced warnings with exact grants: %v", warns)
	}
	want := Rule{
		ID:       "project.terraform-apply",
		Tool:     "Bash",
		Pattern:  "terraform apply*",
		Decision: Ask,
		Reason:   "infrastructure change requires operator review",
	}
	if !slices.Contains(merged.Rules, want) {
		t.Fatalf("merged rules do not contain the example rule: %+v", merged.Rules)
	}
	if !slices.Contains(merged.Slots.EgressAllowlist, "api.github.com") {
		t.Fatalf("exactly granted example egress entry was not merged: %v", merged.Slots.EgressAllowlist)
	}
}

func TestOverlayTooLargeIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guardrail.toml")
	big := bytes.Repeat([]byte{'#'}, (1<<20)+1)
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOverlay(p); err == nil {
		t.Fatal("an oversized overlay must be rejected, not parsed")
	}
}

func TestOversizedOverlayIsRejectedBeforeParsing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guardrail.toml")
	big := bytes.Repeat([]byte{'['}, (1<<20)+1)
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadOverlay(p)
	if err == nil || !strings.Contains(err.Error(), "over the 1048576 limit") {
		t.Fatalf("an oversized malformed overlay must fail the size check first: %v", err)
	}
}

func TestNormalOverlayStillLoads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guardrail.toml")
	if err := os.WriteFile(p, []byte("engine_min_version = \"1.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOverlay(p); err != nil {
		t.Fatalf("a normal overlay must load: %v", err)
	}
}

func TestOverlayExactlyAtSizeLimitStillLoads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guardrail.toml")
	prefix := []byte("engine_min_version = \"1.0\"\n#")
	raw := append(prefix, bytes.Repeat([]byte{'x'}, (1<<20)-len(prefix))...)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOverlay(p); err != nil {
		t.Fatalf("an overlay exactly at the size limit must load: %v", err)
	}
}

func TestLoadOverlayPreservesReadErrors(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "missing.toml")
		if _, err := LoadOverlay(p); err == nil || !strings.Contains(err.Error(), "reading overlay "+p) {
			t.Fatalf("missing overlay must retain the read error: %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		p := t.TempDir()
		if _, err := LoadOverlay(p); err == nil || !strings.Contains(err.Error(), "reading overlay "+p) {
			t.Fatalf("unreadable overlay must retain the read error: %v", err)
		}
	})
}
