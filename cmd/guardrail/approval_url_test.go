package main

import (
	"bytes"
	"testing"
)

func TestPrintOperatorURL(t *testing.T) {
	var output bytes.Buffer
	if err := printOperatorURL(&output, "http://localhost:39169"); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "guardrail: open operator approval page:\nhttp://localhost:39169\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
