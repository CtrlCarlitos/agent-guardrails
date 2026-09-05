package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOperatorConfig(t *testing.T, body string) {
	t.Helper()
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	dir := filepath.Join(base, "guardrail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "waivers.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorConfigPathUsesPlatformConfigDirectory(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Unix environment-variable behavior")
	}

	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if got, want := OperatorConfigPath(), filepath.Join(xdg, "guardrail", "waivers.toml"); got != want {
		t.Fatalf("OperatorConfigPath() = %q, want %q", got, want)
	}

	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)
	if got, want := OperatorConfigPath(), filepath.Join(home, ".config", "guardrail", "waivers.toml"); got != want {
		t.Fatalf("OperatorConfigPath() without XDG_CONFIG_HOME = %q, want %q", got, want)
	}
}

func TestOperatorConfigMissingIsEmptyNotError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	o, err := LoadOperatorConfig()
	if err != nil {
		t.Fatalf("missing config must not error: %v", err)
	}
	if o.AllowsWaiver("/any/repo", "P6.egress") {
		t.Error("empty config must authorize nothing")
	}
}

func TestOperatorConfigGrantsPerRepo(t *testing.T) {
	writeOperatorConfig(t, `
["/home/u/trusted"]
waive = ["P6.egress", "P1.chmod"]
secret_allow = true
`)
	o, err := LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !o.AllowsWaiver("/home/u/trusted", "P6.egress") {
		t.Error("granted waiver not honoured")
	}
	if o.AllowsWaiver("/home/u/other", "P6.egress") {
		t.Error("a grant must not transfer to a different repo")
	}
	if o.AllowsWaiver("/home/u/trusted", "P1.rm-rf") {
		t.Error("only listed rule ids may be waived")
	}
	if !o.AllowsSecretAllow("/home/u/trusted") {
		t.Error("secret_allow grant not honoured")
	}
	if o.AllowsAuditLog("/home/u/trusted") {
		t.Error("audit_log defaults to false when unset")
	}
}

func TestOperatorConfigRepoMatchIsCleanAndExact(t *testing.T) {
	writeOperatorConfig(t, `
["/home/u/trusted/./"]
waive = ["P6.egress"]
secret_allow = true
audit_log = true
`)
	o, err := LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}

	if !o.AllowsWaiver("/home/u/trusted/../trusted", "P6.egress") {
		t.Error("equivalent cleaned repo path must match")
	}
	for _, repo := range []string{"/home/u/trusted/subrepo", "/home/u/trusted-other"} {
		if o.AllowsWaiver(repo, "P6.egress") || o.AllowsSecretAllow(repo) || o.AllowsAuditLog(repo) {
			t.Errorf("grant for /home/u/trusted must not cross repo boundary to %s", repo)
		}
	}
}

func TestOperatorConfigRejectsNonAbsoluteRepoGrant(t *testing.T) {
	writeOperatorConfig(t, `
["relative/repo"]
waive = ["P6.egress"]
`)
	o, err := LoadOperatorConfig()
	if err == nil {
		t.Fatal("non-absolute repository grant must return an error")
	}
	if o.AllowsWaiver("relative/repo", "P6.egress") {
		t.Error("non-absolute repository grant must authorize nothing")
	}
}

func TestOperatorConfigMalformedReturnsEmptyConfigAndError(t *testing.T) {
	writeOperatorConfig(t, `["/home/u/trusted"`)
	o, err := LoadOperatorConfig()
	if err == nil {
		t.Fatal("malformed operator config must return an error")
	}
	if !strings.Contains(err.Error(), "parsing operator config") {
		t.Fatalf("error must identify parse operation: %v", err)
	}
	if o == nil || o.AllowsWaiver("/home/u/trusted", "P6.egress") {
		t.Error("malformed operator config must return a non-nil config authorizing nothing")
	}
}

func TestOperatorConfigReadError(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	path := filepath.Join(base, "guardrail", "waivers.toml")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}

	o, err := LoadOperatorConfig()
	if err == nil {
		t.Fatal("operator config read failure must return an error")
	}
	if !strings.Contains(err.Error(), "reading operator config") {
		t.Fatalf("error must identify read operation: %v", err)
	}
	if o == nil {
		t.Error("read failure must return a non-nil empty config")
	}
}

func TestBackstopsAreNeverWaivable(t *testing.T) {
	writeOperatorConfig(t, `
["/home/u/trusted"]
waive = ["tokenize-failed", "panic-recovered", "P3.unresolved"]
`)
	o, err := LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"tokenize-failed", "panic-recovered", "P3.unresolved"} {
		if o.AllowsWaiver("/home/u/trusted", id) {
			t.Errorf("%s must never be waivable, even by the operator", id)
		}
	}
}

func TestOperatorConfigNilSafe(t *testing.T) {
	var o *OperatorConfig
	if o.AllowsWaiver("/x", "P6.egress") || o.AllowsSecretAllow("/x") || o.AllowsAuditLog("/x") {
		t.Error("a nil OperatorConfig must authorize nothing")
	}
}
