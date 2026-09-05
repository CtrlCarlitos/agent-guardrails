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

func assertEmptyOperatorConfig(t *testing.T, o *OperatorConfig) {
	t.Helper()
	if o == nil {
		t.Fatal("error must return a non-nil empty config")
	}
	if o.Repos == nil {
		t.Fatal("error must return an initialized repos map")
	}
	if len(o.Repos) != 0 {
		t.Fatalf("error must return no grants, got %v", o.Repos)
	}
	if o.AllowsWaiver("/home/u/trusted", "P6.egress") || o.AllowsSecretAllow("/home/u/trusted") ||
		o.AllowsAuditLog("/home/u/trusted") || o.AllowsEgress("/home/u/trusted", "api.example.com") {
		t.Error("error config must authorize nothing")
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

func TestOperatorConfigRejectsInvalidConfigRoot(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Unix environment-variable behavior")
	}

	tests := []struct {
		name string
		xdg  string
		home string
		want string
	}{
		{name: "relative XDG_CONFIG_HOME", xdg: "relative/config", home: t.TempDir(), want: "XDG_CONFIG_HOME"},
		{name: "relative HOME fallback", home: "relative/home", want: "home directory"},
		{name: "unavailable HOME fallback", home: "", want: "home directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", tt.xdg)
			t.Setenv("HOME", tt.home)
			if got := OperatorConfigPath(); got != "" {
				t.Fatalf("invalid config root produced path %q", got)
			}
			o, err := LoadOperatorConfig()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadOperatorConfig() error = %v, want contextual %q error", err, tt.want)
			}
			assertEmptyOperatorConfig(t, o)
		})
	}
}

func TestOperatorConfigRejectsInvalidWindowsConfigRoot(t *testing.T) {
	tests := []struct {
		name    string
		appData string
	}{
		{name: "absent", appData: ""},
		{name: "relative", appData: "relative/appdata"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("APPDATA", tt.appData)
			if path, err := operatorConfigPath("windows"); err == nil || path != "" {
				t.Fatalf("operatorConfigPath(windows) = %q, %v; want empty path and error", path, err)
			}
		})
	}
}

func TestOperatorConfigPathUsesAbsoluteWindowsConfigDirectory(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)
	got, err := operatorConfigPath("windows")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(appData, "guardrail", "waivers.toml"); got != want {
		t.Fatalf("operatorConfigPath(windows) = %q, want %q", got, want)
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
	if !o.AllowsAuditLog("/home/u/trusted") {
		t.Error("audit_log grant not honoured")
	}
	for _, repo := range []string{"/home/u/trusted/subrepo", "/home/u/trusted-other"} {
		if o.AllowsWaiver(repo, "P6.egress") || o.AllowsSecretAllow(repo) || o.AllowsAuditLog(repo) {
			t.Errorf("grant for /home/u/trusted must not cross repo boundary to %s", repo)
		}
	}
}

func TestOperatorConfigEgressGrantRequiresExactEntryAndRepo(t *testing.T) {
	writeOperatorConfig(t, `
["/home/u/trusted/./"]
egress_allowlist = ["api.example.com", "*.trusted.example"]
`)
	o, err := LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range []string{"api.example.com", "*.trusted.example"} {
		if !o.AllowsEgress("/home/u/trusted/../trusted", entry) {
			t.Errorf("exact egress entry %q was not authorized for cleaned repository path", entry)
		}
	}
	for _, entry := range []string{"API.example.com", "api.example.com.", "trusted.example", "sub.trusted.example"} {
		if o.AllowsEgress("/home/u/trusted", entry) {
			t.Errorf("non-exact egress entry %q was authorized", entry)
		}
	}
	for _, repo := range []string{"/home/u/trusted/subrepo", "/home/u/trusted-other", "/home/u/Trusted", "home/u/trusted"} {
		if o.AllowsEgress(repo, "api.example.com") {
			t.Errorf("egress grant crossed exact repository boundary to %q", repo)
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
	assertEmptyOperatorConfig(t, o)
}

func TestOperatorConfigMixedValidAndInvalidGrantsReturnsEmpty(t *testing.T) {
	const body = `
["/home/u/trusted"]
waive = ["P6.egress"]

["relative/repo"]
waive = ["P1.chmod"]
`
	// TOML tables decode into a map, so exercise varying iteration orders.
	for range 100 {
		writeOperatorConfig(t, body)
		o, err := LoadOperatorConfig()
		if err == nil {
			t.Fatal("mixed absolute and relative repository grants must return an error")
		}
		assertEmptyOperatorConfig(t, o)
	}
}

func TestOperatorConfigRejectsDuplicateCleanedRepoGrant(t *testing.T) {
	writeOperatorConfig(t, `
["/home/u/trusted"]
waive = ["P6.egress"]

["/home/u/trusted/."]
audit_log = true
`)
	o, err := LoadOperatorConfig()
	if err == nil {
		t.Fatal("distinct repository keys that clean to the same path must return an error")
	}
	if !strings.Contains(err.Error(), "same cleaned path") {
		t.Fatalf("error must identify cleaned-path collision: %v", err)
	}
	assertEmptyOperatorConfig(t, o)
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
	assertEmptyOperatorConfig(t, o)
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
	assertEmptyOperatorConfig(t, o)
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
	if o.AllowsWaiver("/x", "P6.egress") || o.AllowsSecretAllow("/x") || o.AllowsAuditLog("/x") || o.AllowsEgress("/x", "api.example.com") {
		t.Error("a nil OperatorConfig must authorize nothing")
	}
}
