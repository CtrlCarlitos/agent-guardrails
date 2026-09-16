package approval

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
)

// Browser is a loopback-only approval page. The random URL token prevents a
// different local page from submitting an approval without seeing the request.
type Browser struct {
	server *http.Server
	listen net.Listener
}

func StartBrowser(broker *Broker, requestID string) (*Browser, string, error) {
	if broker == nil || requestID == "" {
		return nil, "", ErrMalformed
	}
	if _, err := broker.Request(requestID); err != nil {
		return nil, "", err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	token, err := browserToken()
	if err != nil {
		listener.Close()
		return nil, "", err
	}
	browser := &Browser{listen: listener}
	browser.server = &http.Server{Handler: browserHandler(broker, requestID, token)}
	go browser.server.Serve(listener) // Close terminates this loop.
	return browser, fmt.Sprintf("http://%s/?token=%s", listener.Addr(), token), nil
}

func (b *Browser) Close() error {
	if b == nil || b.server == nil {
		return nil
	}
	return b.server.Close()
}

func browserHandler(broker *Broker, requestID, token string) http.Handler {
	page := template.Must(template.New("approval").Parse(`<!doctype html><title>Guardrail approval</title><h1>Guardrail approval</h1><dl><dt>Plane</dt><dd>{{.Plane}}</dd><dt>Repository</dt><dd>{{.RepoRoot}}</dd><dt>Host</dt><dd>{{.Host}}</dd><dt>Action</dt><dd>{{.Action}}</dd><dt>Scope</dt><dd>{{.Scope}}</dd><dt>Expires</dt><dd>{{.ExpiresAt}}</dd></dl><form method="post"><input type="hidden" name="token" value="{{.Token}}"><button name="choice" value="approve">Approve</button><button name="choice" value="deny">Deny</button></form>`))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != token && r.FormValue("token") != token {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			req, err := broker.Request(requestID)
			if err != nil || req.Status != "pending" {
				http.Error(w, "request unavailable", http.StatusGone)
				return
			}
			_ = page.Execute(w, struct {
				Request
				Token string
			}{req, token})
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var err error
		switch r.FormValue("choice") {
		case "approve":
			req, getErr := broker.Request(requestID)
			if getErr != nil {
				err = getErr
			} else {
				err = broker.Approve(requestID, req.Scope)
			}
		case "deny":
			err = broker.Deny(requestID)
		default:
			err = ErrMalformed
		}
		if err != nil {
			http.Error(w, "request unavailable", http.StatusGone)
			return
		}
		fmt.Fprint(w, "completed")
	})
}

func browserToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
