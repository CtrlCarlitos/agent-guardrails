package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #125: `guardrail fetch` said only "requires operator approval", so an agent
// had no command to run and stopped. The ask names the exact grant.
func TestFetchAskForUnapprovedHostNamesTheExactGrant(t *testing.T) {
	_, v, err := Fetch(context.Background(), "https://starship.rs/presets/", &policy.Policy{})
	if err != nil || v.Decision != policy.Ask {
		t.Fatalf("Fetch = %+v, %v", v, err)
	}
	if want := policy.WebHostGrantCommand("starship.rs"); !strings.Contains(v.Reason, want) {
		t.Fatalf("reason %q does not name %q", v.Reason, want)
	}
}

func TestFetchAskForUnapprovedRedirectNamesTheRedirectHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://docs.example.com/", http.StatusFound)
	}))
	defer server.Close()
	_, v, err := Fetch(context.Background(), server.URL, &policy.Policy{})
	if err != nil || v.Decision != policy.Ask {
		t.Fatalf("Fetch = %+v, %v", v, err)
	}
	if want := policy.WebHostGrantCommand("docs.example.com"); !strings.Contains(v.Reason, want) {
		t.Fatalf("reason %q does not name %q", v.Reason, want)
	}
}
