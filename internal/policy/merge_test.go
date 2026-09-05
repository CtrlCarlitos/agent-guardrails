package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func mergeNoOp(t *testing.T, base *Policy, ov *Overlay) (*Policy, []string) {
	t.Helper()
	m, warns, err := Merge(base, ov, "1.0.0", &OperatorConfig{Repos: map[string]RepoGrant{}}, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	return m, warns
}

func TestMergePreservesBaseAndAppendsTightenings(t *testing.T) {
	base := &Policy{
		Slots: Slots{
			SafeRoots:       []string{"/base/safe"},
			SecretGlobs:     []string{"**/.env"},
			SecretAllow:     []string{"/base/public"},
			EgressAllowlist: []string{"base.example.com"},
			AuditLog:        "/base/audit.jsonl",
		},
		Rules:  []Rule{{ID: "base-rule", Decision: Deny}},
		Waived: map[string]bool{"base-waiver": true},
	}
	ov := &Overlay{
		SafeRoots:       []string{"tmp"},
		SecretGlobs:     []string{"*.p12"},
		EgressAllowlist: []string{"api.example.com"},
		Rules:           []Rule{{ID: "overlay-ask", Decision: Ask}, {ID: "overlay-deny", Decision: Deny}},
	}

	op := &OperatorConfig{Repos: map[string]RepoGrant{
		"/repo": {EgressAllowlist: []string{"api.example.com"}},
	}}
	m, warns, err := Merge(base, ov, "1.0.0", op, "/repo")
	if err != nil {
		t.Fatal(err)
	}

	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if !slices.Equal(m.Slots.SafeRoots, []string{"/base/safe", "tmp"}) {
		t.Errorf("SafeRoots = %v", m.Slots.SafeRoots)
	}
	if !slices.Equal(m.Slots.SecretGlobs, []string{"**/.env", "*.p12"}) {
		t.Errorf("SecretGlobs = %v", m.Slots.SecretGlobs)
	}
	if !slices.Equal(m.Slots.SecretAllow, []string{"/base/public"}) {
		t.Errorf("SecretAllow = %v", m.Slots.SecretAllow)
	}
	if !slices.Equal(m.Slots.EgressAllowlist, []string{"base.example.com", "api.example.com"}) {
		t.Errorf("EgressAllowlist = %v", m.Slots.EgressAllowlist)
	}
	if m.Slots.AuditLog != "/base/audit.jsonl" {
		t.Errorf("AuditLog = %q", m.Slots.AuditLog)
	}
	if !slices.Equal(m.Rules, []Rule{{ID: "base-rule", Decision: Deny}, {ID: "overlay-ask", Decision: Ask}, {ID: "overlay-deny", Decision: Deny}}) {
		t.Errorf("Rules = %v", m.Rules)
	}
	if !m.Waived["base-waiver"] {
		t.Error("base waiver was not preserved")
	}

	m.Slots.SafeRoots[0] = "changed"
	m.Slots.SecretGlobs[0] = "changed"
	m.Slots.SecretAllow[0] = "changed"
	m.Slots.EgressAllowlist[0] = "changed"
	m.Rules[0].ID = "changed"
	m.Waived["base-waiver"] = false
	if base.Slots.SafeRoots[0] != "/base/safe" || base.Slots.SecretGlobs[0] != "**/.env" ||
		base.Slots.SecretAllow[0] != "/base/public" || base.Slots.EgressAllowlist[0] != "base.example.com" ||
		base.Rules[0].ID != "base-rule" || !base.Waived["base-waiver"] {
		t.Fatal("Merge mutated Base policy storage")
	}
}

func TestMergePartiallyAuthorizedWaivers(t *testing.T) {
	op := &OperatorConfig{Repos: map[string]RepoGrant{
		"/repo": {Waive: []string{"P6.egress"}},
	}}
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{Waive: []string{"P6.egress", "P1.rm-rf"}}

	m, warns, err := Merge(base, ov, "1.0.0", op, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Waived["P6.egress"] {
		t.Error("authorized waiver was not recorded")
	}
	if m.Waived["P1.rm-rf"] {
		t.Error("unauthorized waiver was recorded")
	}
	if len(warns) != 2 || !strings.Contains(warns[0], "P6.egress is WAIVED") ||
		!strings.Contains(warns[1], "waiver of P1.rm-rf") || !strings.Contains(warns[1], "NOT authorized") {
		t.Fatalf("waiver warnings = %v", warns)
	}
}

func TestMergeBackstopsAreDroppedEvenWhenGranted(t *testing.T) {
	ids := []string{"tokenize-failed", "panic-recovered", "P3.unresolved"}
	op := &OperatorConfig{Repos: map[string]RepoGrant{"/repo": {Waive: ids}}}

	m, warns, err := Merge(&Policy{Waived: map[string]bool{}}, &Overlay{Waive: ids}, "1.0.0", op, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if m.Waived[id] {
			t.Errorf("backstop %s was waived", id)
		}
	}
	if len(warns) != len(ids) {
		t.Fatalf("got %d warnings, want one per backstop: %v", len(warns), warns)
	}
	for i, id := range ids {
		if !strings.Contains(warns[i], id) || !strings.Contains(warns[i], "can never be waived") {
			t.Errorf("warning %d = %q", i, warns[i])
		}
	}
}

func TestMergeNilOrMissingOperatorConfigAuthorizesNothing(t *testing.T) {
	for _, tt := range []struct {
		name string
		op   *OperatorConfig
	}{
		{name: "nil", op: nil},
		{name: "missing file result", op: &OperatorConfig{Repos: map[string]RepoGrant{}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := &Policy{Slots: Slots{AuditLog: "/base/audit.jsonl"}, Waived: map[string]bool{}}
			ov := &Overlay{
				Waive:       []string{"P6.egress"},
				SecretAllow: []string{"public/**"},
				EgressAllowlist: []string{
					"api.example.com",
				},
				AuditLog: "/tmp/repo-audit.jsonl",
			}

			m, warns, err := Merge(base, ov, "1.0.0", tt.op, "/repo")
			if err != nil {
				t.Fatal(err)
			}
			if m.Waived["P6.egress"] || len(m.Slots.SecretAllow) != 0 || len(m.Slots.EgressAllowlist) != 0 || m.Slots.AuditLog != "/base/audit.jsonl" {
				t.Fatalf("unauthorized loosening took effect: %+v", m)
			}
			if len(warns) != 4 {
				t.Fatalf("warnings = %v, want one for each dropped request", warns)
			}
		})
	}
}

func TestMergeSecretAllowAndAuditLogRequireExactRepoGrant(t *testing.T) {
	op := &OperatorConfig{Repos: map[string]RepoGrant{
		"/repo": {SecretAllow: true, AuditLog: true},
	}}
	base := &Policy{Slots: Slots{AuditLog: "/base/audit.jsonl"}, Waived: map[string]bool{}}
	ov := &Overlay{SecretAllow: []string{"public/**"}, AuditLog: "/repo/audit.jsonl"}

	for _, repoRoot := range []string{"/repo/subrepo", "/repo-other", "repo"} {
		m, warns, err := Merge(base, ov, "1.0.0", op, repoRoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Slots.SecretAllow) != 0 || m.Slots.AuditLog != "/base/audit.jsonl" || len(warns) != 2 {
			t.Errorf("repo %q crossed exact grant boundary: policy=%+v warnings=%v", repoRoot, m, warns)
		}
	}

	m, warns, err := Merge(base, ov, "1.0.0", op, "/repo/./")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.SecretAllow, []string{"public/**"}) || m.Slots.AuditLog != "/repo/audit.jsonl" {
		t.Fatalf("exact cleaned grant was not applied: %+v", m)
	}
	if len(warns) != 0 {
		t.Fatalf("authorized changes warned: %v", warns)
	}
}

func TestMergeSafeRootsMustResolveUnderAbsoluteRepoRoot(t *testing.T) {
	ov := &Overlay{SafeRoots: []string{
		"tmp",
		".",
		"../project-sibling",
		"../other",
		"/work/project/assets",
		"/work/project-prefix",
		"/etc",
	}}

	m, warns, err := Merge(&Policy{Waived: map[string]bool{}}, ov, "1.0.0", nil, "/work/project")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.SafeRoots, []string{"tmp", ".", "/work/project/assets"}) {
		t.Errorf("SafeRoots = %v", m.Slots.SafeRoots)
	}
	wantDropped := []string{"../project-sibling", "../other", "/work/project-prefix", "/etc"}
	if len(warns) != len(wantDropped) {
		t.Fatalf("warnings = %v, want one per external root", warns)
	}
	for i, root := range wantDropped {
		if !strings.Contains(warns[i], root) || !strings.Contains(warns[i], "DROPPED") {
			t.Errorf("warning %d = %q", i, warns[i])
		}
	}
}

func TestMergeSafeRootsHaveNoOperatorEscapeGrant(t *testing.T) {
	op := &OperatorConfig{Repos: map[string]RepoGrant{
		"/repo": {Waive: []string{"P1.rm-rf"}, SecretAllow: true, AuditLog: true},
	}}

	m, warns, err := Merge(&Policy{Waived: map[string]bool{}}, &Overlay{SafeRoots: []string{"/etc"}}, "1.0.0", op, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Slots.SafeRoots) != 0 || len(warns) != 1 {
		t.Fatalf("operator config authorized external safe root: policy=%+v warnings=%v", m, warns)
	}
}

func TestMergeSafeRootsRejectExistingSymlinkEscape(t *testing.T) {
	repoRoot := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(outside, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repoRoot, "escape")); err != nil {
		t.Fatal(err)
	}

	m, warns, err := Merge(&Policy{Waived: map[string]bool{}}, &Overlay{SafeRoots: []string{"escape/existing"}}, "1.0.0", nil, repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Slots.SafeRoots) != 0 || len(warns) != 1 || !strings.Contains(warns[0], "DROPPED") {
		t.Fatalf("symlink escape was accepted: policy=%+v warnings=%v", m, warns)
	}
}

func TestMergeSafeRootsKeepNonexistentChildUnderResolvedInRepoAncestor(t *testing.T) {
	repoRoot := t.TempDir()
	realDir := filepath.Join(repoRoot, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(repoRoot, "alias")); err != nil {
		t.Fatal(err)
	}

	m, warns, err := Merge(&Policy{Waived: map[string]bool{}}, &Overlay{SafeRoots: []string{"alias/future/nested"}}, "1.0.0", nil, repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.SafeRoots, []string{"alias/future/nested"}) || len(warns) != 0 {
		t.Fatalf("nonexistent in-repo descendant was dropped: policy=%+v warnings=%v", m, warns)
	}
}

func TestMergeSafeRootsFailClosedWithoutAbsoluteRepoRoot(t *testing.T) {
	for _, repoRoot := range []string{"", "relative/repo"} {
		m, warns, err := Merge(&Policy{Waived: map[string]bool{}}, &Overlay{SafeRoots: []string{"tmp", "/etc"}}, "1.0.0", nil, repoRoot)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Slots.SafeRoots) != 0 || len(warns) != 2 {
			t.Errorf("repo root %q did not fail closed: policy=%+v warnings=%v", repoRoot, m, warns)
		}
	}
}

func TestMergeEgressRequiresExactGrantAndRejectsTotalWildcards(t *testing.T) {
	op := &OperatorConfig{Repos: map[string]RepoGrant{
		"/repo": {EgressAllowlist: []string{"*", "**", "*.example.com", "api.github.com"}},
	}}
	m, warns, err := Merge(&Policy{Waived: map[string]bool{}}, &Overlay{
		EgressAllowlist: []string{"*", "**", "*.example.com", "api.github.com"},
	}, "1.0.0", op, "/repo")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(m.Slots.EgressAllowlist, []string{"*.example.com", "api.github.com"}) {
		t.Errorf("EgressAllowlist = %v", m.Slots.EgressAllowlist)
	}
	if len(warns) != 2 || !strings.Contains(warns[0], "entry *") || !strings.Contains(warns[1], "entry **") {
		t.Fatalf("wildcard warnings = %v", warns)
	}
}

func TestMergeEgressGrantDoesNotTransferAcrossEntryOrRepo(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	configPath := filepath.Join(configHome, "guardrail", "waivers.toml")
	op := &OperatorConfig{Repos: map[string]RepoGrant{
		"/repo": {EgressAllowlist: []string{"api.example.com"}},
	}}
	base := &Policy{Slots: Slots{EgressAllowlist: []string{"base.example.com"}}, Waived: map[string]bool{}}
	ov := &Overlay{EgressAllowlist: []string{"API.example.com", "other.example.com", "api.example.com"}}

	for _, repoRoot := range []string{"/repo/subrepo", "/repo-other"} {
		m, warns, err := Merge(base, ov, "1.0.0", op, repoRoot)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(m.Slots.EgressAllowlist, []string{"base.example.com"}) {
			t.Errorf("repo %q crossed exact grant boundary: %v", repoRoot, m.Slots.EgressAllowlist)
		}
		if len(warns) != 3 {
			t.Errorf("repo %q warnings = %v, want one per rejected entry", repoRoot, warns)
		}
	}

	m, warns, err := Merge(base, ov, "1.0.0", op, "/repo/./")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.EgressAllowlist, []string{"base.example.com", "api.example.com"}) {
		t.Fatalf("exact grant merge = %v", m.Slots.EgressAllowlist)
	}
	want := []string{
		"guardrail: repo requested egress_allowlist entry API.example.com, which is NOT authorized in " + configPath + " — DROPPED",
		"guardrail: repo requested egress_allowlist entry other.example.com, which is NOT authorized in " + configPath + " — DROPPED",
	}
	if !slices.Equal(warns, want) {
		t.Fatalf("warnings = %#v, want %#v", warns, want)
	}
}

func TestMergeEgressCannotBeAuthorizedByOtherGrants(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	op := &OperatorConfig{Repos: map[string]RepoGrant{
		"/repo": {Waive: []string{"P6.egress"}, SecretAllow: true, AuditLog: true},
	}}
	base := &Policy{Slots: Slots{EgressAllowlist: []string{"base.example.com"}}, Waived: map[string]bool{}}
	ov := &Overlay{EgressAllowlist: []string{"api.example.com"}}

	m, warns, err := Merge(base, ov, "1.0.0", op, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.EgressAllowlist, []string{"base.example.com"}) {
		t.Fatalf("unrelated operator grants authorized egress: %v", m.Slots.EgressAllowlist)
	}
	want := "guardrail: repo requested egress_allowlist entry api.example.com, which is NOT authorized in " +
		filepath.Join(configHome, "guardrail", "waivers.toml") + " — DROPPED"
	if !slices.Equal(warns, []string{want}) {
		t.Fatalf("warnings = %#v, want %#v", warns, []string{want})
	}
}

func TestMergeDroppedRequestWarningsAreStable(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	configPath := filepath.Join(configHome, "guardrail", "waivers.toml")
	base := &Policy{Slots: Slots{AuditLog: "/base/audit.jsonl"}, Waived: map[string]bool{}}
	ov := &Overlay{
		SafeRoots:        []string{"/outside/one", "/outside/two"},
		SecretAllow:      []string{"one", "two"},
		EgressAllowlist:  []string{"*", "**", "api.example.com"},
		AuditLog:         "/tmp/audit.jsonl",
		Waive:            []string{"P6.egress", "tokenize-failed"},
		EngineMinVersion: "2.0.0",
	}
	want := []string{
		"guardrail: repo requested safe_root /outside/one outside the repository — DROPPED",
		"guardrail: repo requested safe_root /outside/two outside the repository — DROPPED",
		"guardrail: repo requested a wildcard egress_allowlist entry * — DROPPED",
		"guardrail: repo requested a wildcard egress_allowlist entry ** — DROPPED",
		"guardrail: repo requested egress_allowlist entry api.example.com, which is NOT authorized in " + configPath + " — DROPPED",
		"guardrail: repo requested secret_allow entries, which are NOT authorized in " + configPath + " — secret protection remains ENFORCED",
		"guardrail: repo requested audit_log /tmp/audit.jsonl, which is NOT authorized in " + configPath + " — the default audit path is retained",
		"guardrail: repo requested waiver of P6.egress, which is NOT authorized in " + configPath + " — the rule remains ENFORCED",
		"guardrail: rule tokenize-failed can never be waived (fail-closed backstop) — request IGNORED",
		"guardrail: binary 1.0.0 is older than this repo's engine_min_version 2.0.0",
	}

	for range 20 {
		_, warns := mergeNoOp(t, base, ov)
		if !slices.Equal(warns, want) {
			t.Fatalf("warnings = %#v, want %#v", warns, want)
		}
	}
}

func TestMergeNilOverlayCopiesBaseWithoutWarnings(t *testing.T) {
	base := &Policy{Slots: Slots{SafeRoots: []string{"/base"}}, Waived: map[string]bool{"P6.egress": true}}
	m, warns, err := Merge(base, nil, "1.0.0", nil, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.SafeRoots, base.Slots.SafeRoots) || !m.Waived["P6.egress"] || len(warns) != 0 {
		t.Fatalf("nil overlay merge = %+v, warnings=%v", m, warns)
	}
}

func TestMergeRejectsAllowRule(t *testing.T) {
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{Rules: []Rule{{ID: "x", Decision: Allow, Pattern: "curl *"}}}
	if _, _, err := Merge(base, ov, "1.0.0", nil, "/repo"); err == nil {
		t.Fatal("want error for an overlay allow rule")
	}
}

func TestMergeRejectsInvalidOverlayDecision(t *testing.T) {
	for _, d := range []Decision{"Deny", "block", "deny ", ""} {
		base := &Policy{Waived: map[string]bool{}}
		ov := &Overlay{Rules: []Rule{{ID: "x", Decision: d, Pattern: "curl *"}}}
		if _, _, err := Merge(base, ov, "1.0.0", nil, "/repo"); err == nil {
			t.Errorf("decision %q: want error, got nil", d)
		}
	}
}

func TestVersionOlder(t *testing.T) {
	if !versionOlder("1.0.0", "1.2.0") {
		t.Error("1.0.0 < 1.2.0")
	}
	if versionOlder("2.0.0", "1.9.9") {
		t.Error("2.0.0 !< 1.9.9")
	}
	if versionOlder("dev", "1.0.0") {
		t.Error("non-numeric never warns")
	}
}
