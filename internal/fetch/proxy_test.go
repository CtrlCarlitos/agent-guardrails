package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestFetchReturnsNormalizedHTMLAfterAllowedRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<h1>Guardrail</h1><p>fetch</p>"))
	}))
	defer server.Close()

	body, verdict, err := Fetch(context.Background(), server.URL+"/start", &policy.Policy{})
	if err != nil || verdict.Decision != policy.Allow || body != "Guardrail fetch\n" {
		t.Fatalf("Fetch = %q, %+v, %v", body, verdict, err)
	}
}

func TestFetchAsksBeforeFollowingUnapprovedRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusFound)
	}))
	defer server.Close()

	_, verdict, err := Fetch(context.Background(), server.URL, &policy.Policy{})
	if err != nil || verdict.Decision != policy.Ask {
		t.Fatalf("Fetch = %+v, %v", verdict, err)
	}
}
