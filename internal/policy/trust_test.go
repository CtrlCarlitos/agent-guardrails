package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestTrustSnapshotFromOverlayExtractsAndFiltersAllFiveSlots(t *testing.T) {
	ov := &Overlay{
		EgressAllowlist: []string{"z.example.com", "*", "**", "a.example.com", "a.example.com", ""},
		WebHosts:        []string{"docs.example.com", "https://bad.example.com", "api.example.com", "api.example.com"},
		Waive:           []string{"P6.egress", "tokenize-failed", "panic-recovered", "P3.unresolved", "P2.force-push", "P6.egress"},
		SecretAllow:     []string{"fixtures/**", "public/.env.test", "fixtures/**"},
		AuditLog:        "/var/log/guardrail-repo.jsonl",
	}

	got := TrustSnapshotFromOverlay(ov)
	if got == nil {
		t.Fatal("TrustSnapshotFromOverlay returned nil")
	}
	if !slices.Equal(got.EgressAllowlist, []string{"a.example.com", "z.example.com"}) {
		t.Errorf("EgressAllowlist = %v, want [a.example.com z.example.com]", got.EgressAllowlist)
	}
	if !slices.Equal(got.WebHosts, []string{"api.example.com", "docs.example.com"}) {
		t.Errorf("WebHosts = %v, want [api.example.com docs.example.com]", got.WebHosts)
	}
	if !slices.Equal(got.Waive, []string{"P2.force-push", "P6.egress"}) {
		t.Errorf("Waive = %v, want [P2.force-push P6.egress]", got.Waive)
	}
	if !slices.Equal(got.SecretAllow, []string{"fixtures/**", "public/.env.test"}) {
		t.Errorf("SecretAllow = %v, want [fixtures/** public/.env.test]", got.SecretAllow)
	}
	if got.AuditLog != "/var/log/guardrail-repo.jsonl" {
		t.Errorf("AuditLog = %q, want /var/log/guardrail-repo.jsonl", got.AuditLog)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestTrustSnapshotValidateAndDecodeRejectInvalidInputs(t *testing.T) {
	invalid := []struct {
		name string
		snap TrustSnapshot
	}{
		{name: "wildcard egress *", snap: TrustSnapshot{EgressAllowlist: []string{"*"}}},
		{name: "wildcard egress **", snap: TrustSnapshot{EgressAllowlist: []string{"**"}}},
		{name: "empty egress", snap: TrustSnapshot{EgressAllowlist: []string{""}}},
		{name: "invalid web host", snap: TrustSnapshot{WebHosts: []string{"https://example.com"}}},
		{name: "never waivable backstop", snap: TrustSnapshot{Waive: []string{"P3.unresolved"}}},
		{name: "empty secret allow", snap: TrustSnapshot{SecretAllow: []string{""}}},
		{name: "newline in audit log", snap: TrustSnapshot{AuditLog: "a\nb"}},
	}
	for _, tc := range invalid {
		if err := tc.snap.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want error", tc.name)
		}
	}

	// JSON null decodes to nil (revocation).
	revoked, err := DecodeTrustSnapshot("null")
	if err != nil || revoked != nil {
		t.Fatalf("DecodeTrustSnapshot(null) = (%v, %v), want (nil, nil)", revoked, err)
	}
	// Unknown JSON fields and trailing tokens must fail closed.
	if _, err := DecodeTrustSnapshot(`{"unknown":true}`); err == nil {
		t.Error("DecodeTrustSnapshot accepted unknown field")
	}
	if _, err := DecodeTrustSnapshot(`{"waive":["P6.egress"]} trailing`); err == nil {
		t.Error("DecodeTrustSnapshot accepted trailing input")
	}

	orig := &TrustSnapshot{
		EgressAllowlist: []string{"api.example.com"},
		WebHosts:        []string{"docs.example.com"},
		Waive:           []string{"P6.egress"},
		SecretAllow:     []string{"fixtures/**"},
		AuditLog:        "/tmp/custom.jsonl",
	}
	raw, err := EncodeTrustSnapshot(orig)
	if err != nil {
		t.Fatalf("EncodeTrustSnapshot: %v", err)
	}
	decoded, err := DecodeTrustSnapshot(raw)
	if err != nil {
		t.Fatalf("DecodeTrustSnapshot: %v", err)
	}
	if !orig.Equal(decoded) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, orig)
	}
}

func TestOperatorConfigLoadsTrustSnapshotAndRejectsInvalidTrust(t *testing.T) {
	cfgDir := t.TempDir()
	testenv.SetConfig(t, cfgDir)
	repo := operatorRepo("trusted-project")
	guardrailDir := filepath.Join(cfgDir, "guardrail")
	if err := os.MkdirAll(guardrailDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tomlBody := "[" + strconvQuote(repo) + "]\n" +
		"waive = [\"P2.manual\"]\n\n" +
		"[" + strconvQuote(repo) + ".trust]\n" +
		"egress_allowlist = [\"api.example.com\"]\n" +
		"web_hosts = [\"docs.example.com\"]\n" +
		"waive = [\"P6.egress\"]\n" +
		"secret_allow = [\"fixtures/**\"]\n" +
		"audit_log = \"/tmp/trusted.jsonl\"\n"
	if err := os.WriteFile(filepath.Join(guardrailDir, "waivers.toml"), []byte(tomlBody), 0o600); err != nil {
		t.Fatal(err)
	}

	op, err := LoadOperatorConfig()
	if err != nil {
		t.Fatalf("LoadOperatorConfig() error = %v", err)
	}
	snap, ok := op.TrustFor(repo)
	if !ok || snap == nil {
		t.Fatalf("TrustFor(%q) = (%v, %v), want snapshot", repo, snap, ok)
	}
	if !op.AllowsEgress(repo, "api.example.com") {
		t.Error("AllowsEgress did not honor trust snapshot")
	}
	if !op.AllowsWebHost(repo, "docs.example.com") {
		t.Error("AllowsWebHost did not honor trust snapshot")
	}
	if !op.AllowsWaiver(repo, "P6.egress") || !op.AllowsWaiver(repo, "P2.manual") {
		t.Error("AllowsWaiver did not honor both trust snapshot and manual waiver")
	}
	if !op.AllowsSecretAllowEntry(repo, "fixtures/**") || op.AllowsSecretAllowEntry(repo, ".env") {
		t.Error("AllowsSecretAllowEntry did not enforce exact snapshot globs")
	}
	if !op.AllowsAuditLogPath(repo, "/tmp/trusted.jsonl") || op.AllowsAuditLogPath(repo, "/tmp/evil.jsonl") {
		t.Error("AllowsAuditLogPath did not enforce exact snapshot path")
	}

	// Invalid trust snapshot in waivers.toml fails closed.
	badToml := "[" + strconvQuote(repo) + ".trust]\nwaive = [\"tokenize-failed\"]\n"
	if err := os.WriteFile(filepath.Join(guardrailDir, "waivers.toml"), []byte(badToml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperatorConfig(); err == nil {
		t.Fatal("LoadOperatorConfig accepted invalid trust snapshot with neverWaivable rule")
	}
}

func TestMergeHonorsTrustSnapshotAndDeniesNewPRRequests(t *testing.T) {
	repo := operatorRepo("repo")
	trustedAudit := filepath.Join(repo, "trusted-audit.jsonl")
	base := &Policy{
		Slots:  Slots{AuditLog: "/base/audit.jsonl"},
		Waived: map[string]bool{},
	}
	initialOv := &Overlay{
		EgressAllowlist: []string{"api.example.com"},
		WebHosts:        []string{"docs.example.com"},
		Waive:           []string{"P6.egress"},
		SecretAllow:     []string{"fixtures/**"},
		AuditLog:        trustedAudit,
	}
	op := &OperatorConfig{
		Repos: map[string]RepoGrant{
			repo: {Trust: TrustSnapshotFromOverlay(initialOv)},
		},
	}

	// Initial overlay matches snapshot: everything honored with only the active-waiver notice.
	m, warns, err := Merge(base, initialOv, "1.0.0", op, repo)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.Slots.EgressAllowlist, "api.example.com") {
		t.Errorf("trusted egress not honored: %v", m.Slots.EgressAllowlist)
	}
	if !slices.Contains(m.Slots.WebHosts, "docs.example.com") {
		t.Errorf("trusted web_hosts not honored: %v", m.Slots.WebHosts)
	}
	if !m.Waived["P6.egress"] {
		t.Error("trusted waiver not honored")
	}
	if !slices.Contains(m.Slots.SecretAllow, "fixtures/**") {
		t.Errorf("trusted secret_allow not honored: %v", m.Slots.SecretAllow)
	}
	if m.Slots.AuditLog != trustedAudit {
		t.Errorf("trusted audit_log = %q, want %q", m.Slots.AuditLog, trustedAudit)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "P6.egress is WAIVED") {
		t.Fatalf("unexpected warnings for trusted overlay: %v", warns)
	}

	// Simulate a PR adding new requests across every slot: trusted entries stay honored,
	// new entries are dropped with trust-snapshot warnings.
	prOv := &Overlay{
		EgressAllowlist: []string{"api.example.com", "newdomain.example.com"},
		WebHosts:        []string{"docs.example.com", "evil.example.com"},
		Waive:           []string{"P6.egress", "P2.force-push"},
		SecretAllow:     []string{"fixtures/**", "**/.env"},
		AuditLog:        filepath.Join(repo, "evil-audit.jsonl"),
	}
	m2, warns2, err := Merge(base, prOv, "1.0.0", op, repo)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(m2.Slots.EgressAllowlist, "newdomain.example.com") {
		t.Error("new egress domain took effect without re-trust")
	}
	if !slices.Contains(m2.Slots.EgressAllowlist, "api.example.com") {
		t.Error("previously trusted egress domain was lost")
	}
	if slices.Contains(m2.Slots.WebHosts, "evil.example.com") {
		t.Error("new web_host took effect without re-trust")
	}
	if m2.Waived["P2.force-push"] {
		t.Error("new waiver took effect without re-trust")
	}
	if slices.Contains(m2.Slots.SecretAllow, "**/.env") || !slices.Contains(m2.Slots.SecretAllow, "fixtures/**") {
		t.Errorf("SecretAllow = %v, want only trusted fixtures/**", m2.Slots.SecretAllow)
	}
	if m2.Slots.AuditLog != "/base/audit.jsonl" {
		t.Errorf("changed audit_log took effect: %q", m2.Slots.AuditLog)
	}

	joined := strings.Join(warns2, "\n")
	for _, want := range []string{
		"newdomain.example.com",
		"evil.example.com",
		"P2.force-push",
		"**/.env",
		"evil-audit.jsonl",
		"not in trust snapshot",
		"guardrail operator trust",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}
}

func TestDiffTrustClassifiesAuthorizedPendingRemovedAndRejected(t *testing.T) {
	repo := operatorRepo("repo")
	op := &OperatorConfig{
		Repos: map[string]RepoGrant{
			repo: {
				Waive: []string{"P2.manual"},
				Trust: &TrustSnapshot{
					EgressAllowlist: []string{"kept.example.com", "removed.example.com"},
					WebHosts:        []string{"docs.example.com"},
					SecretAllow:     []string{"fixtures/**"},
				},
			},
		},
	}
	ov := &Overlay{
		EgressAllowlist: []string{"kept.example.com", "added.example.com", "*"},
		WebHosts:        []string{"docs.example.com"},
		Waive:           []string{"P2.manual", "P6.egress", "tokenize-failed"},
		SecretAllow:     []string{"fixtures/**", "extra/**"},
	}

	diff := DiffTrust(ov, op, repo)
	if !diff.HasSnapshot {
		t.Fatal("HasSnapshot = false, want true")
	}
	hasItem := func(list []TrustItem, kind, val string) bool {
		for _, it := range list {
			if it.Kind == kind && it.Value == val {
				return true
			}
		}
		return false
	}
	if !hasItem(diff.Authorized, "egress_allowlist", "kept.example.com") ||
		!hasItem(diff.Authorized, "web_hosts", "docs.example.com") ||
		!hasItem(diff.Authorized, "waive", "P2.manual") ||
		!hasItem(diff.Authorized, "secret_allow", "fixtures/**") {
		t.Errorf("Authorized = %+v", diff.Authorized)
	}
	if !hasItem(diff.Pending, "egress_allowlist", "added.example.com") ||
		!hasItem(diff.Pending, "waive", "P6.egress") ||
		!hasItem(diff.Pending, "secret_allow", "extra/**") {
		t.Errorf("Pending = %+v", diff.Pending)
	}
	if !hasItem(diff.Removed, "egress_allowlist", "removed.example.com") {
		t.Errorf("Removed = %+v", diff.Removed)
	}
	if !hasItem(diff.Rejected, "egress_allowlist", "*") || !hasItem(diff.Rejected, "waive", "tokenize-failed") {
		t.Errorf("Rejected = %+v", diff.Rejected)
	}
}

func strconvQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
