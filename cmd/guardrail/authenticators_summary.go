package main

import (
	"fmt"

	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

// operatorCredentials reads the enrolled authenticators' public records. A seam
// so tests can stand in for a store.
var operatorCredentials = func() ([]operatorauth.Credential, error) {
	return defaultOperatorAuthStore().Credentials()
}

// describeAuthenticators answers "which device can approve" from what the
// record already holds (#383): whether each passkey is synced (backup-eligible,
// held by a passkey provider, usable wherever that provider is signed in) or
// device-bound, and whether its transports were recorded. Without transports a
// browser cannot narrow its prompt, so it offers everything, including a phone,
// which can never hold a passkey for the rpId localhost.
func describeAuthenticators(credentials []operatorauth.Credential) string {
	total := len(credentials)
	synced, bound, recorded := 0, 0, 0
	for _, c := range credentials {
		if c.BackupEligible {
			synced++
		} else {
			bound++
		}
		if len(c.Transports) > 0 {
			recorded++
		}
	}
	noun := "authenticators"
	if total == 1 {
		noun = "authenticator"
	}
	text := fmt.Sprintf("%d %s: %d synced (backup-eligible, held by a passkey provider), %d device-bound; transports recorded for %d of %d", total, noun, synced, bound, recorded, total)
	if recorded < total {
		text += " (without them the browser offers every option, including a phone, which cannot hold a passkey for localhost)"
	}
	return text
}
