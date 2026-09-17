package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestFetchDeniesInvalidURLs(t *testing.T) {
	for _, raw := range []string{"example.com", "ftp://example.com", "https://user@example.com", "https://example.com/#fragment"} {
		_, v, err := Fetch(context.Background(), raw, &policy.Policy{})
		if err != nil || v.Decision != policy.Deny {
			t.Errorf("Fetch(%q) = %+v, %v", raw, v, err)
		}
	}
}

func TestFetchAllowsIPv6Loopback(t *testing.T) {
	if !allowed("http://[::1]/", &policy.Policy{}) {
		t.Fatal("IPv6 loopback denied")
	}
}

func TestFetchRejectsUnsafeMediaAndOversizedBodies(t *testing.T) {
	for _, tc := range []struct {
		media, body string
		rule        string
	}{{"application/octet-stream", "x", "fetch-content-type"}, {"text/plain", strings.Repeat("x", maxBody+1), "fetch-too-large"}} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.media)
			w.Write([]byte(tc.body))
		}))
		_, v, _ := Fetch(context.Background(), s.URL, &policy.Policy{})
		s.Close()
		if v.RuleID != tc.rule {
			t.Errorf("%s = %+v", tc.media, v)
		}
	}
}

func TestFetchHonorsContextDeadline(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, v, err := Fetch(ctx, s.URL, &policy.Policy{})
	if err == nil || v.Decision != policy.Deny {
		t.Fatalf("Fetch = %+v, %v", v, err)
	}
}

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
