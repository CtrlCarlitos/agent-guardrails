package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func fullPol() *policy.Policy {
	p := pathPol()
	p.Slots.SafeRoots = []string{"/repo/tmp"}
	p.Rules = []policy.Rule{
		// Deliberately a command with no built-in rule. The fixture used
		// `terraform apply*` until #235 gave terraform a built-in verdict,
		// at which point both overlay tests below started measuring the
		// built-in instead of the overlay they exist to test.
		{ID: "proj.tf", Pattern: "projdeploy sync*", Decision: policy.Ask, Reason: "infra"},
	}
	return p
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		tc   ToolCall
		want policy.Decision
		id   string
	}{
		{ToolCall{Tool: "Bash", Command: "ls -la", CWD: "/repo", RepoRoot: "/repo"}, policy.Allow, ""},
		{ToolCall{Tool: "Bash", Command: "rm -rf /", CWD: "/repo", RepoRoot: "/repo"}, policy.Deny, "P1.rm-rf"},
		{ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, policy.Deny, "P4.secret-path"},
		{ToolCall{Tool: "Bash", Command: "chmod -R 777 /repo", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P1.chmod"},
		{ToolCall{Tool: "Bash", Command: "projdeploy sync --now", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "proj.tf"},
		{ToolCall{Tool: "Bash", Command: `echo "oops`, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "tokenize-failed"},
	}
	for _, c := range cases {
		v := Evaluate(c.tc, fullPol())
		if v.Decision != c.want || (c.id != "" && v.RuleID != c.id) {
			t.Errorf("Evaluate(%q) = %+v, want %s/%s", c.tc.Command+c.tc.Tool, v, c.want, c.id)
		}
	}
}

func TestUnknownToolAuditsButAllowsInAuditPosture(t *testing.T) {
	p := fullPol()
	p.UnknownToolPosture = policy.UnknownAudit
	v := Evaluate(ToolCall{NativeTool: "new_tool", Capability: policy.CapabilityUnknown}, p)
	if v.Decision != policy.Allow || v.AuditKind != "unknown-native-tool" {
		t.Fatalf("unknown tool audit posture = %+v, want allow/unknown-native-tool", v)
	}
}

func TestUnknownToolDeniesInDenyPosture(t *testing.T) {
	p := fullPol()
	p.UnknownToolPosture = policy.UnknownDeny
	v := Evaluate(ToolCall{NativeTool: "new_tool", Capability: policy.CapabilityUnknown}, p)
	if v.Decision != policy.Deny || v.AuditKind != "unknown-native-tool" {
		t.Fatalf("unknown tool deny posture = %+v, want deny/unknown-native-tool", v)
	}
}

func TestPathCapabilitiesDenyWithoutPaths(t *testing.T) {
	for _, capability := range []policy.Capability{policy.CapabilityReadDiscovery, policy.CapabilityMutation} {
		v := Evaluate(ToolCall{NativeTool: "path_tool", Capability: capability}, fullPol())
		if v.Decision != policy.Deny {
			t.Fatalf("%s without paths = %+v, want deny", capability, v)
		}
	}
}

func TestPathCapabilitiesDenyEmptyPath(t *testing.T) {
	for _, capability := range []policy.Capability{policy.CapabilityReadDiscovery, policy.CapabilityMutation} {
		v := Evaluate(ToolCall{NativeTool: "path_tool", Capability: capability, Paths: []string{""}}, fullPol())
		if v.Decision != policy.Deny {
			t.Fatalf("%s with empty path = %+v, want deny", capability, v)
		}
	}
}

func TestWebFetchCapabilityDeniesMissingOrInvalidURL(t *testing.T) {
	for _, rawURL := range []string{"", "not a URL", "ftp://example.com/file", "https://"} {
		v := Evaluate(ToolCall{NativeTool: "webfetch", Capability: policy.CapabilityWebFetch, URL: rawURL}, fullPol())
		if v.Decision != policy.Deny {
			t.Fatalf("web_fetch %q = %+v, want deny", rawURL, v)
		}
	}
}

func TestCommandCapabilityDeniesWithoutCommand(t *testing.T) {
	v := Evaluate(ToolCall{NativeTool: "command_tool", Capability: policy.CapabilityCommand}, fullPol())
	if v.Decision != policy.Deny {
		t.Fatalf("command without input = %+v, want deny", v)
	}
}

func TestStaticCapabilitiesDispatchWithoutFallback(t *testing.T) {
	cases := []struct {
		capability policy.Capability
		want       policy.Decision
	}{
		{policy.CapabilitySafeControl, policy.Allow},
		{policy.CapabilityDeny, policy.Deny},
		{policy.CapabilityWebSearch, policy.Ask},
		{policy.CapabilityExternal, policy.Ask},
		{policy.CapabilityDelegation, policy.Deny},
		{policy.Capability("invalid"), policy.Deny},
	}
	for _, tt := range cases {
		v := Evaluate(ToolCall{NativeTool: "capability_tool", Capability: tt.capability}, fullPol())
		if v.Decision != tt.want {
			t.Fatalf("%s = %+v, want %s", tt.capability, v, tt.want)
		}
	}
}

func TestExternalCapabilityAsksWithItsOwnRule(t *testing.T) {
	v := Evaluate(ToolCall{Plane: "claude", NativeTool: "mcp__server__tool", Capability: policy.CapabilityExternal}, fullPol())
	if v.Decision != policy.Ask || v.RuleID != "capability-external" || !strings.Contains(v.Reason, "outside the session") {
		t.Fatalf("external = %+v, want ask/capability-external", v)
	}
}

func TestEvaluateWaived(t *testing.T) {
	p := fullPol()
	p.Waived["P1.rm-rf"] = true
	v := Evaluate(ToolCall{Tool: "Bash", Command: "rm -rf /etc", CWD: "/repo", RepoRoot: "/repo"}, p)
	if v.Decision != policy.Allow {
		t.Fatalf("waived rule still fired: %+v", v)
	}
}

func TestEvaluateSecretGlobWaiverStillAllows(t *testing.T) {
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/.env"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Allow {
		t.Fatalf("waived secret glob -> %+v, want allow", v)
	}
}

func TestEvaluateSecretDirIgnoresP4Waiver(t *testing.T) {
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{"/home/u/.ssh/id_rsa"}, CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Fatalf("direct secret-dir path with P4 waiver -> %+v, want deny/P4.secret-path", v)
	}
}

func TestEvaluateResolvedSecretDirIgnoresP4Waiver(t *testing.T) {
	secretDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "id_rsa")
	if err := os.WriteFile(secret, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "innocent")
	if err := os.Symlink(secret, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{alias}, CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Fatalf("resolved secret-dir path with P4 waiver -> %+v, want deny/P4.secret-path", v)
	}
}

func TestEvaluateWaivedLexicalDenyKeepsResolvedAsk(t *testing.T) {
	repo := t.TempDir()
	cert := filepath.Join(repo, "cert.pem")
	if err := os.WriteFile(cert, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(repo, ".env")
	if err := os.Symlink(cert, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := fullPol()
	p.Waived["P4.secret-path"] = true
	tc := ToolCall{Tool: "Read", Paths: []string{alias}, CWD: repo, RepoRoot: repo}
	if v := Evaluate(tc, p); v.Decision != policy.Ask || v.RuleID != "P4.secret-path-ambiguous" {
		t.Fatalf("waived lexical deny plus unwaived resolved ask -> %+v, want ask/P4.secret-path-ambiguous", v)
	}
}

func TestEvaluateStrongestUnwaivedSecretTierOnSameForm(t *testing.T) {
	tc := ToolCall{Tool: "Read", Paths: []string{"/repo/foo-private-key.pem"}, CWD: "/repo", RepoRoot: "/repo"}
	for _, test := range []struct {
		name   string
		waived bool
		want   policy.Decision
		ruleID string
	}{
		{name: "deny wins without waiver", want: policy.Deny, ruleID: "P4.secret-path"},
		{name: "ask survives deny waiver", waived: true, want: policy.Ask, ruleID: "P4.secret-path-ambiguous"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := fullPol()
			p.Waived["P4.secret-path"] = test.waived
			if v := Evaluate(tc, p); v.Decision != test.want || v.RuleID != test.ruleID {
				t.Fatalf("Evaluate() = %+v, want %s/%s", v, test.want, test.ruleID)
			}
		})
	}
}

func TestEvaluateWaivedOverlayRuleStillAllows(t *testing.T) {
	p := fullPol()
	p.Waived["proj.tf"] = true
	tc := ToolCall{Tool: "Bash", Command: "projdeploy sync --now", CWD: "/repo", RepoRoot: "/repo"}
	if v := Evaluate(tc, p); v.Decision != policy.Allow {
		t.Fatalf("waived Overlay rule -> %+v, want allow", v)
	}
}

// Ruling: when a built-in rule and an Overlay rule match the same command,
// the more restrictive Verdict wins (deny > ask > allow) regardless of which
// layer produced it. An Overlay may tighten a built-in but never loosen one.
// At equal severity the built-in's rule ID reports (Evaluate keeps the first
// hit). An operator-authorized Waiver clears either layer by rule ID, after
// which the surviving layer's posture governs.
func TestBuiltInAndOverlayVerdictsCombineBySeverity(t *testing.T) {
	overlay := func(t *testing.T, decision policy.Decision) *policy.Policy {
		t.Helper()
		p := fullPol()
		p.Rules = append(p.Rules, policy.Rule{ID: "proj.deploy", Pattern: "terraform apply*", Decision: decision, Reason: "project deploy posture"})
		return p
	}
	tc := ToolCall{Tool: "Bash", Command: "terraform apply", CWD: "/repo", RepoRoot: "/repo"}

	t.Run("overlay cannot loosen a built-in ask", func(t *testing.T) {
		v := Evaluate(tc, overlay(t, policy.Allow))
		if v.Decision != policy.Ask || v.RuleID != "P6.cloud-mutate" {
			t.Fatalf("built-in ask + overlay allow -> %+v, want ask/P6.cloud-mutate", v)
		}
	})

	t.Run("overlay can tighten a built-in ask", func(t *testing.T) {
		v := Evaluate(tc, overlay(t, policy.Deny))
		if v.Decision != policy.Deny || v.RuleID != "proj.deploy" {
			t.Fatalf("built-in ask + overlay deny -> %+v, want deny/proj.deploy", v)
		}
	})

	t.Run("equal severity reports the built-in rule id", func(t *testing.T) {
		v := Evaluate(tc, overlay(t, policy.Ask))
		if v.Decision != policy.Ask || v.RuleID != "P6.cloud-mutate" {
			t.Fatalf("built-in ask + overlay ask -> %+v, want ask/P6.cloud-mutate", v)
		}
	})

	t.Run("waived built-in falls through to the overlay posture", func(t *testing.T) {
		p := overlay(t, policy.Allow)
		p.Waived["P6.cloud-mutate"] = true
		v := Evaluate(tc, p)
		if v.Decision != policy.Allow {
			t.Fatalf("waived built-in + overlay allow -> %+v, want allow", v)
		}
	})
}

func TestDelegationInheritsEnforcementOnInProcessPlanes(t *testing.T) {
	for _, plane := range []string{"opencode", "claude", "antigravity"} {
		v := Evaluate(ToolCall{Plane: plane, NativeTool: "task", Capability: policy.CapabilityDelegation}, fullPol())
		if v.Decision != policy.Allow || v.RuleID != "delegation-inherited" {
			t.Fatalf("%s delegation = %+v, want allow/delegation-inherited", plane, v)
		}
	}
	// Planes without verified child mediation fail closed.
	for _, plane := range []string{"", "codex"} {
		v := Evaluate(ToolCall{Plane: plane, NativeTool: "task", Capability: policy.CapabilityDelegation}, fullPol())
		if v.Decision != policy.Deny || v.RuleID != "capability-delegation-unverified" {
			t.Fatalf("%q delegation = %+v, want deny/capability-delegation-unverified", plane, v)
		}
	}
}

func TestUnknownToolAsksOnOpencodeAndClaude(t *testing.T) {
	for _, plane := range []string{"opencode", "claude"} {
		v := Evaluate(ToolCall{Plane: plane, NativeTool: "future_unknown_tool", Capability: policy.CapabilityUnknown}, fullPol())
		if v.Decision != policy.Ask || v.RuleID != "unknown-native-tool" {
			t.Fatalf("%s unknown = %+v, want ask/unknown-native-tool", plane, v)
		}
	}
}

func TestUnknownToolAsksOnClaude(t *testing.T) {
	cl := Evaluate(ToolCall{Plane: "claude", NativeTool: "brand_new_tool", Capability: policy.CapabilityUnknown}, fullPol())
	if cl.Decision != policy.Ask || cl.RuleID != "unknown-native-tool" {
		t.Fatalf("claude unknown = %+v, want ask/unknown-native-tool", cl)
	}
}
