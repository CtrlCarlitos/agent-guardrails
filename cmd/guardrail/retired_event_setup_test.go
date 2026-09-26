package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

// #322: a registration from an older release holds a guardrail-owned group under
// an event this binary no longer emits. `guardrail setup` re-checks
// setupEnableReason after the approved merge and used to exit 1 with "still
// differs after approval", on every run, because the merge never removed that
// group. The merge now does, and the check converges.

func seedRetiredEventGroup(t *testing.T, plane string) {
	t.Helper()
	path, err := planeConfigPath(plane)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	container := "hooks"
	if plane == "antigravity" {
		container = "guardrail"
	}
	events, _ := doc[container].(map[string]any)
	operator := map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": "operator-retired-event"}}}
	retired := map[string]any{"id": "guardrail-" + plane + "-retired", "matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": "guardrail hook " + plane}}}
	events["RetiredEvent"] = []any{retired, operator}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSetupConvergesWhenAnOlderRegistrationHoldsAGroupUnderARetiredEvent(t *testing.T) {
	for _, plane := range []string{"claude", "antigravity"} {
		t.Run(plane, func(t *testing.T) {
			driftSandbox(t)
			enableForDrift(t, plane)
			useInstalledPlanes(t, plane)
			stubOperatorEnrolled(t, true)
			seedRetiredEventGroup(t, plane)

			reason, err := setupEnableReason(plane)
			if err != nil {
				t.Fatal(err)
			}
			if reason == "" {
				t.Fatal("the leftover owned group does not read as drift; the test's premise is wrong")
			}

			// The approved merge, in reconcile mode as setup runs it.
			if err := enablePlaneIntegrationMode(plane, true, false); err != nil {
				t.Fatal(err)
			}
			reason, err = setupEnableReason(plane)
			if err != nil {
				t.Fatal(err)
			}
			if reason != "" {
				t.Fatalf("still differs after the approved merge (the exit-1 case in setup): %q", reason)
			}
			path, _ := planeConfigPath(plane)
			settings := readPlaneJSON(t, path)
			if strings.Contains(settings, plane+"-retired") {
				t.Errorf("the retired owned group is still on disk:\n%s", settings)
			}
			if !strings.Contains(settings, "operator-retired-event") {
				t.Errorf("the operator's group under the same event was removed:\n%s", settings)
			}
		})
	}
}
