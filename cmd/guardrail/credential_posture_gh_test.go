package main

import (
	"errors"
	"strings"
	"testing"
)

// #544: doctor already probes `gh auth status`, but every failure — not
// logged in, invalid token, timeout — collapses into "no signal", so the
// operator cannot distinguish an account problem from a policy denial
// before a GitHub workflow stalls. The probe's outcomes must be reported
// separately, and an inconclusive check (timeout, exec failure) must never
// be labeled unauthenticated.
func TestGhAuthOutcomeClassification(t *testing.T) {
	cases := []struct {
		name string
		in   ghAuthProbe
		want ghAuthState
	}{
		{"healthy", ghAuthProbe{ran: true, ok: true, output: "✓ Logged in to github.com account work (~/.config/gh/hosts.yml)\n- Active account: work\nToken scopes: 'repo', 'gist'\n"}, ghAuthHealthy},
		{"not logged in", ghAuthProbe{ran: true, output: "You are not logged into any GitHub hosts. Run gh auth login to authenticate.\n", exitError: errGhAuthStatus}, ghAuthNoAccount},
		{"invalid token", ghAuthProbe{ran: true, output: "✗ Logged in to github.com account work (~/.config/gh/hosts.yml)\n- Token for work is invalid.\n", exitError: errGhAuthStatus}, ghAuthInvalid},
		{"empty failure is inconclusive not unauthenticated", ghAuthProbe{ran: true, output: "", exitError: errors.New("exit status 4")}, ghAuthInconclusive},
		{"unrecognized failure stays inconclusive", ghAuthProbe{ran: true, output: "something unprecedented\n", exitError: errors.New("exit status 4")}, ghAuthInconclusive},
		{"timeout is inconclusive", ghAuthProbe{inconclusive: true}, ghAuthInconclusive},
		{"never ran is unavailable", ghAuthProbe{}, ghAuthUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.state(); got != tc.want {
				t.Fatalf("state() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The healthy line must not claim more than CLI auth: the issue is explicit
// that an authentication warning neither implies nor disproves connector or
// capability authorization.
func TestCredentialPostureGhAuthLines(t *testing.T) {
	cases := []struct {
		name string
		in   credentialPostureInput
		want []string
		bad  []string
	}{
		{
			name: "no account warns with the login step",
			in:   credentialPostureInput{ghProbe: ghAuthProbe{ran: true, output: "You are not logged into any GitHub hosts.\n", exitError: errGhAuthStatus}},
			want: []string{"WARNING: gh has no authenticated account", "gh auth login"},
		},
		{
			name: "invalid warns without claiming cause",
			in:   credentialPostureInput{ghProbe: ghAuthProbe{ran: true, output: "✗ Logged in to github.com account work (~/.config/gh/hosts.yml)\n- Token for work is invalid.\n", exitError: errGhAuthStatus}},
			want: []string{"WARNING: gh authentication is invalid or unverified", "gh auth status"},
			bad:  []string{"not logged in", "re-login"},
		},
		{
			name: "inconclusive never says unauthenticated",
			in:   credentialPostureInput{ghProbe: ghAuthProbe{inconclusive: true}},
			want: []string{"gh authentication could not be verified"},
			bad:  []string{"not logged in", "unauthenticated", "gh auth login"},
		},
		{
			// The file's pinned contract: an unavailable probe reports
			// nothing, so a gh-less machine reads as no finding. The
			// taxonomy still distinguishes unavailable (test above) from
			// healthy and from each failure shape.
			name: "cli unavailable stays silent",
			in:   credentialPostureInput{},
			want: nil,
		},
		{
			name: "healthy reports cli-only scope",
			in:   credentialPostureInput{ghProbe: ghAuthProbe{ran: true, ok: true}},
			want: []string{"gh authentication: healthy"},
			bad:  []string{"authorized"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := credentialPostureLines(tc.in)
			joined := strings.Join(lines, "\n")
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Errorf("lines lack %q:\n%s", want, joined)
				}
			}
			for _, banned := range tc.bad {
				if strings.Contains(joined, banned) {
					t.Errorf("lines contain banned %q:\n%s", banned, joined)
				}
			}
		})
	}
}

// The parser must keep its no-secrets promise while learning the failure
// shapes: token material never reaches a reported line, but the unusable
// active account is named.
func TestParseGhAuthFailureShapes(t *testing.T) {
	out := "✗ Logged in to github.com account work (~/.config/gh/hosts.yml)\n- Token for work is invalid. Misconfigurated token or revoked\n✓ Logged in to github.com account personal (keyring)\n- Active account: work\nToken: ghp_secretmaterial\n"
	probe := ghAuthProbe{ran: true, output: out, exitError: errGhAuthStatus}
	if probe.state() != ghAuthInvalid {
		t.Fatalf("mixed valid/invalid accounts with a failing exit = %v, want invalid", probe.state())
	}
	lines := credentialPostureLines(credentialPostureInput{ghProbe: probe})
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "ghp_secretmaterial") {
		t.Fatalf("token material reached a reported line:\n%s", joined)
	}
	if !strings.Contains(joined, "work") {
		t.Fatalf("the unusable active account should be named:\n%s", joined)
	}
}
