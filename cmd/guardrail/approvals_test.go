package main

import (
	"io"
	"strings"
	"testing"
)

func TestApprovalsRejectsTTYClientMode(t *testing.T) {
	if got := cmdApprovalsInput([]string{"--request", "known"}, true, strings.NewReader("y\n"), io.Discard, io.Discard); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
}
