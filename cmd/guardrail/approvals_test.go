package main

import (
	"io"
	"testing"
)

func TestApprovalsRefusesNonTerminal(t *testing.T) {
	if code := cmdApprovals([]string{"--request", "x"}, false, io.Discard, io.Discard); code == 0 {
		t.Fatal("accepted piped approval command")
	}
}
