package engine

import "testing"

func TestOperatorActionRecognizesOnlyCanonicalNightCommands(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"guardrail night off", "night-off"},
		{"guardrail night on --until 08:00", "night-on"},
		{"guardrail night on --for 8h", ""},
		{"/usr/local/bin/guardrail night off", ""},
		{"guardrail night off; rm -rf /", ""},
		{"python3 -c 'guardrail night off'", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: tt.command})
			if (ok && action.Name != tt.want) || (!ok && tt.want != "") {
				t.Fatalf("OperatorAction(%q) = (%+v, %v), want %q", tt.command, action, ok, tt.want)
			}
		})
	}
}

func TestOperatorActionRecognizesOnlyCanonicalWebHostCommands(t *testing.T) {
	tests := []struct {
		command string
		want    string
		scope   string
		host    string
	}{
		{"guardrail egress grant --scope repo --host api.example.test", "web-host-grant", "repo", "api.example.test"},
		{"guardrail egress revoke --scope global --host api.example.test", "web-host-revoke", "global", "api.example.test"},
		{"guardrail egress grant --host api.example.test --scope repo", "", "", ""},
		{"guardrail egress grant --scope repo --host https://api.example.test", "", "", ""},
		{"guardrail egress grant --scope repo --host api.example.test:443", "", "", ""},
		{"guardrail egress grant --scope repo --host '*.example.test'", "", "", ""},
		{"guardrail egress grant --scope repo --host API.example.test", "", "", ""},
		{"guardrail egress grant --scope repo --host api.example.test; id", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: tt.command})
			if (ok && action.Name != tt.want) || (!ok && tt.want != "") || action.Parameters["scope"] != tt.scope || action.Parameters["host"] != tt.host {
				t.Fatalf("OperatorAction(%q) = (%+v, %v), want %q %q %q", tt.command, action, ok, tt.want, tt.scope, tt.host)
			}
		})
	}
}
