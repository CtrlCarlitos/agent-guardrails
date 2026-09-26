package main

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

// The command tests stub the approval transport and hand the approved handler
// the request the command built. That skipped the two things a real approval
// goes through: the broker's validation of the request, and its durable store,
// which is where the request the handler finally runs is read back from. Both
// were broken for `plane enable` of an already-registered plane (reconcile,
// and after #357 prune): the broker refused the extra parameters, and the
// store would have dropped them.
//
// useRealBrokerTransport keeps only the human out of the loop: the request
// really goes through Broker.Create, and the handler really runs on the
// request restored from the store.
func useRealBrokerTransport(t *testing.T) {
	t.Helper()
	guardTestHome(t)
	stubOperatorEnrolled(t, true)
	origSubmit, origQuery, origShutdown := submitPlaneRequest, queryPlaneStatus, setupShutdownDaemon
	t.Cleanup(func() {
		submitPlaneRequest, queryPlaneStatus, setupShutdownDaemon = origSubmit, origQuery, origShutdown
	})
	setupShutdownDaemon = func(string) error { return nil }
	broker := approval.New()
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		created, err := broker.Create(request)
		if errors.Is(err, approval.ErrMalformed) {
			return approval.Request{}, errors.New("approval request malformed")
		}
		if err != nil {
			return approval.Request{}, err
		}
		return approval.Request{ID: created.ID, Status: "pending", ApprovalURL: "http://localhost/approve", ExpiresAt: created.ExpiresAt}, nil
	}
	queryPlaneStatus = func(_, id string) (approval.Request, error) {
		restored, err := broker.Request(id)
		if err != nil {
			return approval.Request{Status: "denied"}, nil
		}
		if err := executePlaneApproval(restored); err != nil {
			return approval.Request{Status: "denied"}, nil
		}
		return approval.Request{Status: "approved"}, nil
	}
}

// The exact case from the field: antigravity is registered with a hook command
// from an older binary, and `plane enable antigravity` has to rewrite it.
func TestPlaneEnableRewritesARegisteredPlaneThroughTheRealBroker(t *testing.T) {
	a, b := driftSandbox(t)
	enableForDrift(t, "antigravity")
	useInstalledExecutable(t, b) // the binary moved: registered handlers now differ
	useInstalledPlanes(t, "antigravity")
	useRealBrokerTransport(t)

	var out, errb strings.Builder
	code := runPlaneTerminal(t, []string{"plane", "enable", "antigravity"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	settings := readPlaneJSON(t, mustPlanePath(t, "antigravity"))
	if !strings.Contains(settings, genconfig.HookCommand(b, "hook", "antigravity", "pre")) && !strings.Contains(settings, strings.ReplaceAll(b, `\`, "/")) {
		t.Fatalf("the hook still points at the old binary %s:\n%s", a, settings)
	}
	if strings.Contains(settings, strings.ReplaceAll(a, `\`, "/")) {
		t.Fatalf("the old binary path %s is still registered:\n%s", a, settings)
	}
}

// #357 through the same door: the approved request must arrive at the handler
// with prune_floor, or the passkey approves a removal that never happens.
func TestPlaneEnablePrunesTheFloorThroughTheRealBroker(t *testing.T) {
	path := seedFlooredClaude(t)
	useInstalledPlanes(t, "claude")
	useRealBrokerTransport(t)

	var out, errb strings.Builder
	code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "floor entries guardrail wrote earlier") {
		t.Errorf("the prune was not announced before the approval:\n%s", out.String())
	}
	if got := settingsList(t, path, "deny"); !slices.Equal(got, []string{"Bash(my-own-deny *)"}) {
		t.Fatalf("deny = %v, want only the operator's entry: the approved prune never ran", got)
	}
	if got := settingsList(t, path, "allow"); !slices.Equal(got, []string{"Bash(graft:*)", "Bash(guardrail fetch:*)"}) {
		t.Fatalf("allow = %v, want untouched", got)
	}
}
