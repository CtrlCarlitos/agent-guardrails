package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
)

// Browser is a loopback-only WebAuthn approval page.
type Browser struct {
	server *http.Server
	listen net.Listener

	broker    *Broker
	authStore AssertionStore
	requestID string
	origin    string
	ceremony  Assertion
	mu        sync.Mutex
	closeOnce sync.Once
}

// Assertion is the browser's public WebAuthn challenge.
type Assertion struct {
	ID      string
	Options any
}

// AssertionStore is the operator-authentication ceremony boundary.
type AssertionStore interface {
	BeginApprovalAssertion(Request, string) (Assertion, error)
	FinishApprovalAssertion(string, []byte) error
}

func StartBrowser(broker *Broker, authStore AssertionStore, requestID string) (*Browser, string, error) {
	if broker == nil || authStore == nil || requestID == "" {
		return nil, "", ErrMalformed
	}
	req, err := broker.Request(requestID)
	if err != nil {
		return nil, "", err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		return nil, "", err
	}
	origin := "http://localhost:" + port
	ceremony, err := authStore.BeginApprovalAssertion(req, origin)
	if err != nil {
		listener.Close()
		return nil, "", err
	}
	browser := &Browser{listen: listener, broker: broker, authStore: authStore, requestID: requestID, origin: origin, ceremony: ceremony}
	browser.server = &http.Server{Handler: browserHandler(browser)}
	go browser.server.Serve(listener) // Close terminates this loop.
	return browser, origin, nil
}

func (b *Browser) Close() error {
	if b == nil || b.server == nil {
		return nil
	}
	var err error
	b.closeOnce.Do(func() { err = b.server.Close() })
	return err
}

func (b *Browser) closeAfterResponse() {
	if b == nil || b.server == nil {
		return
	}
	b.closeOnce.Do(func() {
		go func() { _ = b.server.Shutdown(context.Background()) }()
	})
}

// Handler exposes the assertion-only loopback handler for in-process hosts and tests.
func (b *Browser) Handler() http.Handler {
	if b == nil {
		return http.NotFoundHandler()
	}
	return browserHandler(b)
}

func (b *Browser) reissue(req Request) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	ceremony, err := b.authStore.BeginApprovalAssertion(req, b.origin)
	if err == nil {
		b.ceremony = ceremony
	}
	return err
}

func (b *Browser) currentCeremony() Assertion {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ceremony
}

func publicKeyOptions(options any) any {
	assertion, ok := options.(*protocol.CredentialAssertion)
	if !ok {
		return nil
	}
	return assertion.Response
}

func (b *Browser) finish(req Request, assertion []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.authStore.FinishApprovalAssertion(b.ceremony.ID, assertion); err != nil {
		ceremony, beginErr := b.authStore.BeginApprovalAssertion(req, b.origin)
		if beginErr == nil {
			b.ceremony = ceremony
		}
		return err
	}
	return nil
}

func browserHandler(browser *Browser) http.Handler {
	page := template.Must(template.New("approval").Parse(`<!doctype html><title>Guardrail approval</title><h1>Guardrail approval</h1><dl><dt>Request</dt><dd>{{.RequestIDPrefix}}</dd><dt>Plane</dt><dd>{{.Plane}}</dd><dt>Repository</dt><dd>{{.RepoRoot}}</dd><dt>Host</dt><dd>{{.Host}}</dd><dt>Action</dt><dd>{{.Action}}</dd><dt>Scope</dt><dd>{{.Scope}}</dd><dt>Expires</dt><dd>{{.ExpiresAt}}</dd></dl><output id="status">Waiting for WebAuthn assertion</output><script>const publicKey = {{.Options}};const decode = value => Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");publicKey.challenge = decode(publicKey.challenge);publicKey.allowCredentials = (publicKey.allowCredentials || []).map(credential => ({...credential, id: decode(credential.id)}));window.requestWebAuthnAssertion = () => navigator.credentials.get({publicKey}).then(credential => fetch("/assertion", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:credential.id,rawId:encode(credential.rawId),type:credential.type,response:{authenticatorData:encode(credential.response.authenticatorData),clientDataJSON:encode(credential.response.clientDataJSON),signature:encode(credential.response.signature),userHandle:credential.response.userHandle && encode(credential.response.userHandle)}})})).then(response => {if (response.ok) window.close();else location.reload();}).catch(() => document.getElementById("status").textContent="WebAuthn assertion unavailable");window.requestWebAuthnAssertion();</script>`))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			req, err := browser.broker.Request(browser.requestID)
			if err != nil || req.Status != "pending" {
				http.Error(w, "request unavailable", http.StatusGone)
				browser.closeAfterResponse()
				return
			}
			optionsJSON, err := json.Marshal(publicKeyOptions(browser.currentCeremony().Options))
			if err != nil {
				http.Error(w, "request unavailable", http.StatusGone)
				browser.closeAfterResponse()
				return
			}
			_ = page.Execute(w, struct {
				Request
				Options         template.JS
				RequestIDPrefix string
			}{req, template.JS(optionsJSON), req.ID[:12]})
			return
		case r.Method != http.MethodPost || r.URL.Path != "/assertion":
			http.NotFound(w, r)
			return
		}
		req, err := browser.broker.Request(browser.requestID)
		if err != nil || req.Status != "pending" {
			http.Error(w, "request unavailable", http.StatusGone)
			browser.closeAfterResponse()
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.NotFound(w, r)
			return
		}
		var assertion json.RawMessage
		if json.NewDecoder(r.Body).Decode(&assertion) != nil || len(assertion) == 0 || string(assertion) == "null" {
			http.NotFound(w, r)
			if browser.reissue(req) != nil {
				browser.closeAfterResponse()
			}
			return
		}
		var payload struct {
			ID       string `json:"id"`
			RawID    string `json:"rawId"`
			Type     string `json:"type"`
			Response struct {
				AuthenticatorData string `json:"authenticatorData"`
				ClientDataJSON    string `json:"clientDataJSON"`
				Signature         string `json:"signature"`
			} `json:"response"`
		}
		if json.Unmarshal(assertion, &payload) != nil || payload.ID == "" || payload.RawID == "" || payload.Type != "public-key" || payload.Response.AuthenticatorData == "" || payload.Response.ClientDataJSON == "" || payload.Response.Signature == "" {
			http.NotFound(w, r)
			if browser.reissue(req) != nil {
				browser.closeAfterResponse()
			}
			return
		}
		if err := browser.finish(req, assertion); err != nil {
			http.Error(w, "assertion verification failed", http.StatusForbidden)
			return
		}
		if err := browser.broker.Approve(browser.requestID, req.Scope); err != nil {
			http.Error(w, "request unavailable", http.StatusGone)
			return
		}
		fmt.Fprint(w, "completed")
		browser.closeAfterResponse()
	})
}
