package genconfig

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const opencodeHelperEnv = "GO_WANT_OPENCODE_ENGINE_HELPER"

type testFataler interface {
	Helper()
	Fatal(...any)
}

func writeOpencodeEngine(t testFataler, dir, name string) string {
	t.Helper()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	in, err := os.Open(testBinary)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func init() {
	if os.Getenv(opencodeHelperEnv) != "1" {
		return
	}
	raw, _ := io.ReadAll(os.Stdin)
	if capture := os.Getenv("GUARDRAIL_TEST_CAPTURE"); capture != "" {
		line, _ := bufio.NewReader(strings.NewReader(string(raw))).ReadString('\n')
		f, err := os.OpenFile(capture, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(3)
		}
		_, _ = f.WriteString(strings.TrimSuffix(line, "\n") + "\n")
		_ = f.Close()
	}
	if invoked := os.Getenv("GUARDRAIL_TEST_INVOKED"); invoked != "" {
		_ = os.WriteFile(invoked, []byte("invoked"), 0o600)
	}
	if os.Getenv("GUARDRAIL_TEST_WARNING") == "1" {
		fmt.Fprintln(os.Stderr, "guardrail: session transaction committed but lock release failed (injected release forged claim)")
	}
	responses := map[string]string{
		"":                `{"decision":"allow","reason":"accepted"}`,
		"allow":           `{"decision":"allow","reason":"accepted"}`,
		"ask":             `{"decision":"ask","reason":"Operator authorization required: external egress needs approval. Request authorization for this exact action: bash true. If the operator approves, retry this exact tool call within 10 minutes. If the authorization expires, stop and wait for the operator to return — say what you were doing and that approval expired; do not keep retrying. Do not alter or broaden the action."}`,
		"deny":            `{"decision":"deny","reason":"Guardrail denied this action: protected target. It cannot be authorized. Choose a safe alternative."}`,
		"pending":         `{"decision":"deny","operator_action":"night-on","request_id":"request-1","status":"pending","approval_url":"http://localhost:39169"}`,
		"pending-invalid": `{"decision":"deny","operator_action":"night-on","request_id":"request-1","status":"pending","approval_url":"https://example.test"}`,
		"unknown":         `{"decision":"unexpected","reason":"bad verdict"}`,
		"malformed":       `not-json`,
		"night":           `{"decision":"allow","reason":"NIGHT MODE until 2026-09-11T05:00:00Z; allowed by active night mode"}`,
	}
	fmt.Fprint(os.Stdout, responses[os.Getenv("GUARDRAIL_TEST_RESPONSE")])
	os.Exit(0)
}
