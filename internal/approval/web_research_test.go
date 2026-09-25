package approval_test

import (
	"errors"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func TestWindowsWebResearchRequestValidationAndDurability(t *testing.T) {
	setStateHome(t, t.TempDir())
	for _, mode := range []string{"on", "off", "invalid"} {
		r := request()
		r.Plane = "operator"
		r.Host = ""
		r.Scope = approval.GlobalScope
		r.Action = "web-research-set"
		r.Parameters = map[string]string{"enforcement": mode}
		broker := approval.New()
		created, err := broker.Create(r)
		if mode == "invalid" {
			if !errors.Is(err, approval.ErrMalformed) {
				t.Fatal(err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		stored, err := approval.New().Request(created.ID)
		if err != nil || stored.Parameters["enforcement"] != mode {
			t.Fatalf("restored=%+v err=%v", stored, err)
		}
		if err := broker.Deny(created.ID); err != nil {
			t.Fatal(err)
		}
		if err := broker.Approve(created.ID, approval.GlobalScope); !errors.Is(err, approval.ErrConsumed) {
			t.Fatal(err)
		}
		r.Scope = approval.RepoScope
		if _, err := broker.Create(r); !errors.Is(err, approval.ErrMalformed) {
			t.Fatal("accepted repo scope")
		}
		r.Scope = approval.GlobalScope
		r.Plane = "codex"
		if _, err := broker.Create(r); !errors.Is(err, approval.ErrMalformed) {
			t.Fatal("accepted plane-controlled change")
		}
		r.Plane = "operator"
		r.ExpiresAt = time.Now().Add(-time.Minute)
		created, err = broker.Create(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := broker.Approve(created.ID, approval.GlobalScope); !errors.Is(err, approval.ErrExpired) {
			t.Fatalf("expired approval=%v", err)
		}
	}
}
