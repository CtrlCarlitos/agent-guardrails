package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
	"github.com/go-webauthn/webauthn/protocol"
)

var runOperatorCeremonyFunc = runOperatorCeremony

func cmdOperator(args []string, terminal bool, stdin io.Reader, stdout, stderr io.Writer) int {
	return cmdOperatorInput(args, terminal, stdin, stdout, stderr)
}

func cmdOperatorInput(args []string, terminal bool, stdin io.Reader, stdout, stderr io.Writer) int {
	if !terminal {
		fmt.Fprintln(stderr, "guardrail: operator commands require an interactive local terminal")
		return 2
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: operator requires enroll, add-authenticator, remove-authenticator, or recover-reset")
		return 2
	}
	store := defaultOperatorAuthStore()
	switch args[0] {
	case "enroll":
		if len(args) != 1 {
			return operatorUsage(stderr)
		}
		if enrolled, err := store.Enrolled(); err != nil || enrolled {
			fmt.Fprintln(stderr, "guardrail: initial enrollment requires no enrolled credentials")
			return 2
		}
		if err := runOperatorCeremony(store, "enroll", ""); err != nil {
			fmt.Fprintln(stderr, "guardrail: enrollment did not complete")
			return 1
		}
		fmt.Fprintln(stdout, "guardrail: authenticator enrolled")
		return 0
	case "add-authenticator":
		if len(args) != 1 {
			return operatorUsage(stderr)
		}
		if enrolled, err := store.Enrolled(); err != nil || !enrolled {
			fmt.Fprintln(stderr, "guardrail: authenticator management requires an enrolled credential")
			return 2
		}
		if err := runOperatorCeremonyFunc(store, "add", ""); err != nil {
			fmt.Fprintln(stderr, "guardrail: authenticator addition did not complete")
			return 1
		}
		fmt.Fprintln(stdout, "guardrail: authenticator added")
		return 0
	case "remove-authenticator":
		if len(args) != 2 || args[1] == "" {
			return operatorUsage(stderr)
		}
		credentials, err := store.Credentials()
		if err != nil || len(credentials) < 2 {
			fmt.Fprintln(stderr, "guardrail: cannot remove the final enrolled authenticator")
			return 2
		}
		if err := runOperatorCeremonyFunc(store, "remove", args[1]); err != nil {
			fmt.Fprintln(stderr, "guardrail: authenticator removal did not complete")
			return 1
		}
		fmt.Fprintln(stdout, "guardrail: authenticator removed")
		return 0
	case "recover-reset":
		if len(args) != 1 {
			return operatorUsage(stderr)
		}
		fmt.Fprint(stdout, "Type RESET to remove all enrolled authenticators: ")
		var confirmation string
		if _, err := fmt.Fscan(stdin, &confirmation); err != nil || confirmation != "RESET" {
			fmt.Fprintln(stderr, "guardrail: recovery reset not confirmed")
			return 2
		}
		if err := audit.Write(audit.Record{Plane: "operator", Tool: "guardrail", Event: "operator-auth-recovery", Decision: "requested", OperatorAction: "recover-reset"}, audit.DefaultPath("")); err != nil {
			fmt.Fprintln(stderr, "guardrail: recovery reset audit failed")
			return 1
		}
		if err := store.ClearForRecovery(); err != nil {
			fmt.Fprintln(stderr, "guardrail: recovery reset failed")
			return 1
		}
		if err := audit.Write(audit.Record{Plane: "operator", Tool: "guardrail", Event: "operator-auth-recovery", Decision: "completed", OperatorAction: "recover-reset"}, audit.DefaultPath("")); err != nil {
			fmt.Fprintln(stderr, "guardrail: recovery reset audit failed")
			return 1
		}
		fmt.Fprintln(stdout, "guardrail: approvals disabled until a new authenticator is enrolled")
		return 0
	default:
		return operatorUsage(stderr)
	}
}

func operatorUsage(stderr io.Writer) int {
	fmt.Fprintln(stderr, "guardrail: operator requires enroll, add-authenticator, remove-authenticator <fingerprint>, or recover-reset")
	return 2
}

func runOperatorCeremony(store *operatorauth.Store, operation, fingerprint string) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return err
	}
	origin := "http://localhost:" + port
	page := &operatorPage{store: store, operation: operation, fingerprint: fingerprint, origin: origin, done: make(chan error, 1)}
	if err := page.begin(); err != nil {
		return err
	}
	server := &http.Server{Handler: page.handler()}
	defer server.Shutdown(context.Background())
	go server.Serve(listener) // Shutdown ends this loop.
	if err := openApprovalBrowser(origin); err != nil {
		return err
	}
	select {
	case err := <-page.done:
		return err
	case <-time.After(5 * time.Minute):
		return errors.New("operator WebAuthn ceremony expired")
	}
}

type operatorPage struct {
	store       *operatorauth.Store
	operation   string
	fingerprint string
	origin      string
	ceremony    operatorauth.Ceremony
	done        chan error
}

func (p *operatorPage) begin() error {
	if p.operation == "enroll" {
		ceremony, err := p.store.BeginRegistration(p.origin)
		p.ceremony = ceremony
		return err
	}
	action := "authenticator-add"
	if p.operation == "remove" {
		action = "authenticator-remove"
	}
	parameters := map[string]string(nil)
	if p.operation == "remove" {
		parameters = map[string]string{"credential_fingerprint": p.fingerprint}
	}
	ceremony, err := p.store.BeginAssertion(approval.Request{ID: "operator-management", Plane: "operator", SessionID: "operator", RepoRoot: "/", Scope: approval.Allow, Reason: "local operator management", Action: action, Parameters: parameters, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, p.origin)
	p.ceremony = ceremony
	return err
}

func (p *operatorPage) handler() http.Handler {
	page := template.Must(template.New("operator").Parse(`<!doctype html><title>Guardrail operator</title><h1>Guardrail operator</h1><p>Complete the WebAuthn ceremony with an enrolled authenticator.</p><output id="status">Waiting for WebAuthn</output><script>const publicKey={{.Options}};const mode={{.Mode}};const decode=v=>Uint8Array.from(atob(v.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));const encode=v=>btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""),wire=()=>{publicKey.challenge=decode(publicKey.challenge);if(publicKey.user)publicKey.user.id=decode(publicKey.user.id);publicKey.allowCredentials=(publicKey.allowCredentials||[]).map(c=>({...c,id:decode(c.id)}));};wire();navigator.credentials[mode]({publicKey}).then(c=>fetch("/ceremony",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:c.id,rawId:encode(c.rawId),type:c.type,response:mode==="create"?{clientDataJSON:encode(c.response.clientDataJSON),attestationObject:encode(c.response.attestationObject)}:{authenticatorData:encode(c.response.authenticatorData),clientDataJSON:encode(c.response.clientDataJSON),signature:encode(c.response.signature),userHandle:c.response.userHandle&&encode(c.response.userHandle)}})})).then(r=>{if(r.ok)window.close();else location.reload()}).catch(()=>document.getElementById("status").textContent="WebAuthn ceremony unavailable");</script>`))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			options, mode := operatorOptions(p.ceremony.Options)
			encoded, err := json.Marshal(options)
			if err != nil || options == nil {
				http.Error(w, "ceremony unavailable", http.StatusGone)
				return
			}
			_ = page.Execute(w, struct {
				Options template.JS
				Mode    template.JS
			}{template.JS(encoded), template.JS(fmt.Sprintf("%q", mode))})
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/ceremony" {
			http.NotFound(w, r)
			return
		}
		var response json.RawMessage
		if json.NewDecoder(r.Body).Decode(&response) != nil || len(response) == 0 {
			http.NotFound(w, r)
			return
		}
		if err := p.finish(response); err != nil {
			http.Error(w, "ceremony verification failed", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, "completed")
		select {
		case p.done <- nil:
		default:
		}
	})
}

func operatorOptions(options any) (any, string) {
	switch value := options.(type) {
	case *protocol.CredentialCreation:
		return value.Response, "create"
	case *protocol.CredentialAssertion:
		return value.Response, "get"
	default:
		return nil, ""
	}
}

func (p *operatorPage) finish(response []byte) error {
	switch p.operation {
	case "enroll":
		_, err := p.store.FinishRegistration(p.ceremony.ID, response)
		if err != nil {
			return err
		}
		return nil
	case "add":
		if _, ok := p.ceremony.Options.(*protocol.CredentialAssertion); ok {
			if _, err := p.store.FinishAssertion(p.ceremony.ID, response); err != nil {
				return err
			}
			ceremony, err := p.store.BeginAdditionalRegistration(p.origin)
			if err != nil {
				return err
			}
			p.ceremony = ceremony
			return errors.New("additional registration required")
		}
		credential, err := p.store.FinishRegistration(p.ceremony.ID, response)
		if err != nil {
			return err
		}
		return p.store.AddCredential(credential)
	case "remove":
		if _, err := p.store.FinishAssertion(p.ceremony.ID, response); err != nil {
			return err
		}
		return p.store.RemoveCredentialFingerprint(p.fingerprint)
	default:
		return errors.New("unknown operator management operation")
	}
}
