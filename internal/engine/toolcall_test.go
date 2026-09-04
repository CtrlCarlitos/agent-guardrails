package engine

import "testing"

func TestToolCallIsBash(t *testing.T) {
	if !(ToolCall{Tool: "Bash"}).IsBash() {
		t.Error("Tool=Bash is bash")
	}
	if !(ToolCall{Tool: "bash"}).IsBash() {
		t.Error("case-insensitive")
	}
	if !(ToolCall{Command: "ls"}).IsBash() {
		t.Error("a command string implies bash")
	}
	if (ToolCall{Tool: "Read", Paths: []string{"x"}}).IsBash() {
		t.Error("Read is not bash")
	}
}
