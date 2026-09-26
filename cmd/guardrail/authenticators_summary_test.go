package main

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

// `doctor` said "operator approvals: WebAuthn" and nothing about which
// authenticators back it, so "which device can approve" had no answer (#383).
// The record already carries what is needed: whether a passkey is synced
// (backup-eligible, held by a passkey provider) or device-bound, and whether its
// transports were recorded.

func TestDescribeAuthenticatorsSeparatesSyncedFromDeviceBoundAndCountsTransports(t *testing.T) {
	got := describeAuthenticators([]operatorauth.Credential{
		{ID: "a", BackupEligible: true, BackupState: true},
		{ID: "b", BackupEligible: true, BackupState: true},
		{ID: "c", BackupEligible: false, Transports: []string{"internal"}},
	})
	for _, want := range []string{"3 authenticators", "2 synced", "1 device-bound", "transports recorded for 1 of 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
}

func TestDescribeAuthenticatorsSaysWhyMissingTransportsMatter(t *testing.T) {
	got := describeAuthenticators([]operatorauth.Credential{{ID: "a", BackupEligible: true, BackupState: true}})
	for _, want := range []string{"1 authenticator:", "transports recorded for 0 of 1", "phone"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
}

func TestDescribeAuthenticatorsIsSilentAboutMissingTransportsWhenAllAreRecorded(t *testing.T) {
	got := describeAuthenticators([]operatorauth.Credential{{ID: "a", Transports: []string{"internal"}}})
	if strings.Contains(got, "phone") {
		t.Errorf("%q warns about a problem that is not there", got)
	}
}

func TestDoctorPrintsTheAuthenticatorSummaryWhenAnOperatorIsEnrolled(t *testing.T) {
	driftSandbox(t)
	stubOperatorEnrolled(t, true)
	orig := operatorCredentials
	t.Cleanup(func() { operatorCredentials = orig })
	operatorCredentials = func() ([]operatorauth.Credential, error) {
		return []operatorauth.Credential{{ID: "a", BackupEligible: true, BackupState: true}}, nil
	}
	var out, errb strings.Builder
	cmdDoctor(nil, &out, &errb)
	if !strings.Contains(out.String(), "operator authenticators: 1 authenticator:") {
		t.Fatalf("doctor prints no authenticator summary:\n%s", out.String())
	}
}

func TestDoctorPrintsNoAuthenticatorSummaryWithNoOperator(t *testing.T) {
	driftSandbox(t)
	stubOperatorEnrolled(t, false)
	orig := operatorCredentials
	t.Cleanup(func() { operatorCredentials = orig })
	operatorCredentials = func() ([]operatorauth.Credential, error) { return nil, nil }
	var out, errb strings.Builder
	cmdDoctor(nil, &out, &errb)
	if strings.Contains(out.String(), "operator authenticators:") {
		t.Fatalf("doctor invented an authenticator line:\n%s", out.String())
	}
}
