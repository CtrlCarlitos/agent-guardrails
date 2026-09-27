package approval

import (
	"errors"
	"time"
)

// ErrNoHandler means no action handler is registered for the request's
// action in this process.
var ErrNoHandler = errors.New("no handler registered for the approved action")

// ApplyLocal completes an operator action that prompt mode approved
// (ADR-0033): a host ask answered yes (transport "host-ask") or a terminal
// [y/N] (transport "terminal-prompt"). It applies the broker's validation and
// canonicalisation, then runs the same registered handler the broker runs,
// in-process, so the audit journal and the mutation are identical to a
// passkey-approved action. Nothing is stored with the broker: there is no
// pending state to approve later.
func ApplyLocal(r Request, transport string) (Request, error) {
	if transport == "" {
		return Request{}, ErrMalformed
	}
	if err := validateRequest(r); err != nil {
		return Request{}, err
	}
	now := time.Now().UTC()
	if r.Action == "night-on" {
		expiresAt, err := canonicalNightExpiry(r.Parameters["until"], now)
		if err != nil {
			return Request{}, ErrMalformed
		}
		r.Parameters = map[string]string{"expires_at": expiresAt}
	}
	id, err := randomID()
	if err != nil {
		return Request{}, err
	}
	r.ID = id
	r.IssuedAt = now
	r.ExpiresAt = now.Add(requestTTL)
	r.Status = "executing"
	// The handler sees exactly the shape a broker-approved request has.
	applied := restore(durable(r))
	applied.SessionID = r.SessionID
	applied.Transport = transport
	actionsMu.RLock()
	handler := actions[applied.Action]
	actionsMu.RUnlock()
	if handler == nil {
		return Request{}, ErrNoHandler
	}
	if err := handler(applied); err != nil {
		applied.Status = "failed"
		return applied, err
	}
	applied.Status = "completed"
	return applied, nil
}
