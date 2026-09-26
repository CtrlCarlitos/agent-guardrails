package main

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

// A plane whose settings still carry the floor guardrail used to generate
// (ADR-0028 phases B and C retired it) is reconciled by `plane enable`, which
// removes exactly those entries and keeps the operator's own (#357).

// seedFlooredClaude enables claude in the sandbox, then adds the operator's
// own entries and the retired floor entries an older release wrote.
func seedFlooredClaude(t *testing.T) (settingsPath string) {
	t.Helper()
	driftSandbox(t)
	enableForDrift(t, "claude")
	path, err := planeConfigPath("claude")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	perms, _ := doc["permissions"].(map[string]any)
	if perms == nil {
		perms = map[string]any{}
		doc["permissions"] = perms
	}
	perms["allow"] = []any{"Bash(graft:*)", "Bash(guardrail fetch:*)"}
	perms["deny"] = []any{"Bash(my-own-deny *)", "Bash(dd *)", "Bash(git clean -fd*)", "Bash(sudo *)"}
	perms["ask"] = []any{"Bash(pip install *)"}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func settingsList(t *testing.T, path, tier string) []string {
	t.Helper()
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	perms, _ := doc["permissions"].(map[string]any)
	var out []string
	for _, v := range perms[tier].([]any) {
		out = append(out, v.(string))
	}
	return out
}

func TestEnablePlaneIntegrationModePrunesTheFloorOnlyWhenAsked(t *testing.T) {
	path := seedFlooredClaude(t)

	if err := enablePlaneIntegrationMode("claude", true, false); err != nil {
		t.Fatal(err)
	}
	if got := settingsList(t, path, "deny"); !slices.Contains(got, "Bash(sudo *)") {
		t.Fatalf("a reconcile without the prune flag removed floor entries: %v", got)
	}

	if err := enablePlaneIntegrationMode("claude", true, true); err != nil {
		t.Fatal(err)
	}
	if got := settingsList(t, path, "deny"); !slices.Equal(got, []string{"Bash(my-own-deny *)"}) {
		t.Fatalf("deny = %v, want only the operator's entry", got)
	}
	if got := settingsList(t, path, "allow"); !slices.Equal(got, []string{"Bash(graft:*)", "Bash(guardrail fetch:*)"}) {
		t.Fatalf("allow = %v, want untouched", got)
	}
	doc, _ := genconfig.ReadJSONObject(path)
	if _, ok := doc["permissions"].(map[string]any)["ask"]; ok {
		t.Fatal("an emptied ask tier was left behind")
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("pruning the floor unregistered the hooks")
	}
}

func TestExecutePlaneApprovalPrunesOnlyWhatTheApprovalNames(t *testing.T) {
	path := seedFlooredClaude(t)
	base := approval.Request{Plane: "operator", SessionID: "terminal", Scope: approval.GlobalScope, Action: "plane-enable"}

	plain := base
	plain.ID = "plane-enable-plain"
	plain.Parameters = map[string]string{"planes": "claude", "reconcile_ownership": "claude"}
	if err := executePlaneApproval(plain); err != nil {
		t.Fatal(err)
	}
	if got := settingsList(t, path, "deny"); !slices.Contains(got, "Bash(sudo *)") {
		t.Fatalf("an approval that does not name prune_floor removed floor entries: %v", got)
	}

	named := base
	named.ID = "plane-enable-prune"
	named.Parameters = map[string]string{"planes": "claude", "reconcile_ownership": "claude", "prune_floor": "claude"}
	if err := executePlaneApproval(named); err != nil {
		t.Fatal(err)
	}
	if got := settingsList(t, path, "deny"); !slices.Equal(got, []string{"Bash(my-own-deny *)"}) {
		t.Fatalf("deny = %v, want only the operator's entry", got)
	}
}

func TestExecutePlaneApprovalRejectsAMalformedPruneParameter(t *testing.T) {
	driftSandbox(t)
	for name, r := range map[string]approval.Request{
		"plane not in the batch": {ID: "a", Action: "plane-enable", Parameters: map[string]string{"planes": "antigravity", "prune_floor": "claude"}},
		"plane with no floor":    {ID: "b", Action: "plane-enable", Parameters: map[string]string{"planes": "antigravity", "prune_floor": "antigravity"}},
		"on a disable":           {ID: "c", Action: "plane-disable", Parameters: map[string]string{"planes": "claude", "prune_floor": "claude"}},
	} {
		r.Plane, r.SessionID, r.Scope = "operator", "terminal", approval.GlobalScope
		if err := executePlaneApproval(r); err == nil {
			t.Errorf("%s: want an invalid-action error, got nil", name)
		}
	}
}

// The approval-less bootstrap path can only tighten (ADR-0030); removing a
// deny entry loosens. Even with entries present, and even though the reason
// text would otherwise say to re-enable, bootstrap must not prune.
func TestSetupEnableReasonNamesTheFloorOnlyForAnEnrolledOperator(t *testing.T) {
	path := seedFlooredClaude(t)

	stubOperatorEnrolled(t, true)
	reason, err := setupEnableReason("claude")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "floor entries") || !strings.Contains(reason, "removes") {
		t.Fatalf("enrolled: reason = %q, want it to say floor entries will be removed", reason)
	}

	stubOperatorEnrolled(t, false)
	reason, err = setupEnableReason("claude")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reason, "floor entries") {
		t.Fatalf("not enrolled: reason = %q, must not promise a removal bootstrap cannot make", reason)
	}
	if got := settingsList(t, path, "deny"); !slices.Contains(got, "Bash(sudo *)") {
		t.Fatalf("reading the reason changed the file: %v", got)
	}
}

func TestSetupEnableReasonIsQuietOncePruned(t *testing.T) {
	seedFlooredClaude(t)
	stubOperatorEnrolled(t, true)
	if err := enablePlaneIntegrationMode("claude", true, true); err != nil {
		t.Fatal(err)
	}
	reason, err := setupEnableReason("claude")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reason, "floor entries") {
		t.Fatalf("reason = %q after the prune, want no floor mention", reason)
	}
}
