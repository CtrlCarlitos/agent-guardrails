package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestDeliveryStatusUnconfiguredDoesNotAuthorize(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	var out, stderr bytes.Buffer
	code := run([]string{"delivery", "status"}, strings.NewReader(""), &out, &stderr)
	if code != 0 || !strings.Contains(out.String(), "disabled") {
		t.Fatalf("status must report disabled without requesting approval: exit=%d out=%q err=%q", code, out.String(), stderr.String())
	}
}

func TestDeliveryFinishWithoutAuthorizationFailsClosed(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	var out, stderr bytes.Buffer
	code := run([]string{"delivery", "finish", "--pr", "123"}, strings.NewReader(""), &out, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "not enabled") {
		t.Fatalf("unconfigured finish must name missing repository authorization: exit=%d out=%q err=%q", code, out.String(), stderr.String())
	}
}
