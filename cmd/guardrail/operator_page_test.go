package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

// The store keeps an authenticator's transports when the registration response
// carries them, and uses them to build the approval prompt: with `internal` the
// browser offers this device, and without any it offers everything, including a
// phone that can never hold a passkey for localhost. The enrollment page never
// sent them, so every stored credential has `transports: null` (#383).
func TestOperatorEnrollmentPageSendsTheAuthenticatorTransports(t *testing.T) {
	store := operatorauth.NewStore(t.TempDir())
	page := &operatorPage{store: &store, operation: "enroll", origin: "http://localhost:12345", done: make(chan error, 1)}
	if err := page.begin(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(page.handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	text := string(body)
	if !strings.Contains(text, "getTransports") {
		t.Fatalf("the enrollment page does not read the authenticator's transports:\n%s", text)
	}
	if !strings.Contains(text, "transports:") {
		t.Fatalf("the enrollment page does not post the transports it reads:\n%s", text)
	}
}

// A browser that does not implement getTransports must not break enrollment.
func TestOperatorEnrollmentPageToleratesABrowserWithoutGetTransports(t *testing.T) {
	store := operatorauth.NewStore(t.TempDir())
	page := &operatorPage{store: &store, operation: "enroll", origin: "http://localhost:12345", done: make(chan error, 1)}
	if err := page.begin(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(page.handler())
	defer server.Close()
	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "getTransports?") && !strings.Contains(string(body), "typeof") && !strings.Contains(string(body), "getTransports&&") {
		t.Fatalf("the page calls getTransports without guarding for a browser that lacks it:\n%s", body)
	}
}
