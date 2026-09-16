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
