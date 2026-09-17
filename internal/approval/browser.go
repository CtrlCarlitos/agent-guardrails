package approval

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
)

// Browser is a loopback-only WebAuthn approval page.
type Browser struct {
	server *http.Server
	listen net.Listener
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
	browser := &Browser{listen: listener}
	browser.server = &http.Server{Handler: browserHandler(broker, authStore, requestID, ceremony.ID, ceremony.Options)}
	go browser.server.Serve(listener) // Close terminates this loop.
	return browser, origin, nil
}

func (b *Browser) Close() error {
	if b == nil || b.server == nil {
		return nil
	}
	return b.server.Close()
}

func browserHandler(broker *Broker, authStore AssertionStore, requestID, ceremonyID string, options any) http.Handler {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		panic(err)
	}
	page := template.Must(template.New("approval").Parse(`<!doctype html><title>Guardrail approval</title><h1>Guardrail approval</h1><dl><dt>Plane</dt><dd>{{.Plane}}</dd><dt>Repository</dt><dd>{{.RepoRoot}}</dd><dt>Host</dt><dd>{{.Host}}</dd><dt>Action</dt><dd>{{.Action}}</dd><dt>Scope</dt><dd>{{.Scope}}</dd><dt>Expires</dt><dd>{{.ExpiresAt}}</dd></dl><script>const publicKey = {{.Options}};const decode = value => Uint8Array.from(atob(value.replace(/-/g,"+").replace(/_/g,"/")), c => c.charCodeAt(0));const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");publicKey.challenge = decode(publicKey.challenge);publicKey.allowCredentials = (publicKey.allowCredentials || []).map(credential => ({...credential, id: decode(credential.id)}));navigator.credentials.get({publicKey}).then(credential => fetch("/assertion", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:credential.id,rawId:encode(credential.rawId),type:credential.type,response:{authenticatorData:encode(credential.response.authenticatorData),clientDataJSON:encode(credential.response.clientDataJSON),signature:encode(credential.response.signature),userHandle:credential.response.userHandle && encode(credential.response.userHandle)}})})).then(response => {if (response.ok) window.close();});</script>`))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			req, err := broker.Request(requestID)
			if err != nil || req.Status != "pending" {
				http.Error(w, "request unavailable", http.StatusGone)
				return
			}
			_ = page.Execute(w, struct {
				Request
				Options template.JS
			}{req, template.JS(optionsJSON)})
			return
		case r.Method != http.MethodPost || r.URL.Path != "/assertion":
			http.NotFound(w, r)
			return
		}
		req, err := broker.Request(requestID)
		if err != nil || req.Status != "pending" {
			http.Error(w, "request unavailable", http.StatusGone)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.NotFound(w, r)
			return
		}
		var assertion json.RawMessage
		if json.NewDecoder(r.Body).Decode(&assertion) != nil || len(assertion) == 0 || string(assertion) == "null" {
			http.NotFound(w, r)
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
			return
		}
		if err := authStore.FinishApprovalAssertion(ceremonyID, assertion); err != nil {
			http.Error(w, "assertion verification failed", http.StatusForbidden)
			return
		}
		if err := broker.Approve(requestID, req.Scope); err != nil {
			http.Error(w, "request unavailable", http.StatusGone)
			return
		}
		fmt.Fprint(w, "completed")
	})
}
