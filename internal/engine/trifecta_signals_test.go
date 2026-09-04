package engine

import "testing"

func TestIsPrivateDataAccess(t *testing.T) {
	pol := pathPol()
	if !IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, pol) {
		t.Error("want true for a secret path")
	}
	if IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"src/main.go"}}, pol) {
		t.Error("want false for a non-secret path")
	}
	if !IsPrivateDataAccess(ToolCall{Tool: "Bash", Command: "cat ~/.aws/credentials"}, pol) {
		t.Error("want true for a bash reader of a secret path")
	}
	if IsPrivateDataAccess(ToolCall{Tool: "Read", Paths: []string{"/repo/.env.example"}}, pol) {
		t.Error("want false for an allowlisted secret-adjacent path")
	}
}

func TestIsNetworkAttempt(t *testing.T) {
	if !IsNetworkAttempt(ToolCall{Tool: "Bash", Command: "curl https://example.com"}) {
		t.Error("want true for curl")
	}
	if IsNetworkAttempt(ToolCall{Tool: "Bash", Command: "ls -la"}) {
		t.Error("want false for ls")
	}
	if IsNetworkAttempt(ToolCall{Tool: "Read", Paths: []string{"x"}}) {
		t.Error("want false for a non-bash tool call")
	}
}
