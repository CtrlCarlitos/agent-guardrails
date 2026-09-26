package approval_test

import (
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// `plane enable` on a plane that is already registered sends more than the
// plane list: reconcile_ownership (#335) and, when the retired settings floor
// is still on disk, prune_floor (#357). The broker rejected every such
// request as malformed, and the daemon reported it as the opaque "approval
// request unavailable", so re-enabling a registered plane could not be
// approved at all. The transport is stubbed in the command tests, which call
// the approved handler directly and never met the broker's validation or its
// store; these tests go through both.

func planeRequest(action string, params map[string]string) approval.Request {
	r := request()
	r.Host = ""
	r.Scope = approval.GlobalScope
	r.Action = action
	r.Parameters = params
	return r
}

func TestPlaneEnableCarriesReconcileAndPruneThroughTheBroker(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := approval.New()
	sent := map[string]string{
		"planes":              "claude,antigravity",
		"reconcile_ownership": "claude,antigravity",
		"prune_floor":         "claude",
	}
	created, err := broker.Create(planeRequest("plane-enable", maps.Clone(sent)))
	if err != nil {
		t.Fatalf("Create rejected a well-formed plane-enable: %v", err)
	}
	// What the daemon hands the approved handler is the restored request, read
	// back from the durable store. Anything the store dropped is a change the
	// operator approved and the handler never sees.
	restored, err := broker.Request(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(restored.Parameters, sent) {
		t.Fatalf("restored parameters = %v, want %v", restored.Parameters, sent)
	}
}

func TestPlaneEnableStillAcceptsThePlainPlaneList(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := approval.New()
	created, err := broker.Create(planeRequest("plane-enable", map[string]string{"planes": "claude"}))
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := broker.Request(created.ID)
	if !maps.Equal(restored.Parameters, map[string]string{"planes": "claude"}) {
		t.Fatalf("restored parameters = %v", restored.Parameters)
	}
}

func TestPlaneRequestParametersAreWhitelistedAndBoundToThePlanes(t *testing.T) {
	setStateHome(t, t.TempDir())
	broker := approval.New()
	for name, r := range map[string]approval.Request{
		"reconcile names a plane outside the batch": planeRequest("plane-enable", map[string]string{"planes": "claude", "reconcile_ownership": "opencode"}),
		"prune names a plane outside the batch":     planeRequest("plane-enable", map[string]string{"planes": "claude", "prune_floor": "opencode"}),
		"prune on a plane that never had a floor":   planeRequest("plane-enable", map[string]string{"planes": "antigravity", "prune_floor": "antigravity"}),
		"prune on codex, which keeps its floor":     planeRequest("plane-enable", map[string]string{"planes": "codex", "prune_floor": "codex"}),
		"reconcile on a disable":                    planeRequest("plane-disable", map[string]string{"planes": "claude", "reconcile_ownership": "claude"}),
		"prune on a disable":                        planeRequest("plane-disable", map[string]string{"planes": "claude", "prune_floor": "claude"}),
		"empty reconcile list":                      planeRequest("plane-enable", map[string]string{"planes": "claude", "reconcile_ownership": ""}),
		"unknown extra key":                         planeRequest("plane-enable", map[string]string{"planes": "claude", "extra": "1"}),
		"reconcile without the plane list":          planeRequest("plane-enable", map[string]string{"reconcile_ownership": "claude"}),
	} {
		if _, err := broker.Create(r); !errors.Is(err, approval.ErrMalformed) {
			t.Errorf("%s: accepted (err=%v), want ErrMalformed", name, err)
		}
	}
}

// The passkey covers exactly what the operator is shown, so the summary has to
// say that an enable also removes the retired floor.
func TestPlaneEnableSummaryStatesThePrune(t *testing.T) {
	plain := planeRequest("plane-enable", map[string]string{"planes": "claude"}).Summary()
	if plain != "planes: claude" {
		t.Fatalf("plain summary = %q", plain)
	}
	withPrune := planeRequest("plane-enable", map[string]string{"planes": "claude,antigravity", "reconcile_ownership": "claude,antigravity", "prune_floor": "claude"}).Summary()
	for _, want := range []string{"planes: claude,antigravity", "removes retired settings floor entries", "claude"} {
		if !strings.Contains(withPrune, want) {
			t.Errorf("summary %q lacks %q", withPrune, want)
		}
	}
}
