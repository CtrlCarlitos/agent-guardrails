package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func pathPol() *policy.Policy {
	return &policy.Policy{
		Slots: policy.Slots{
			SecretGlobs: []string{
				"**/.env", ".env.*", "**/.env.*",
				"**/.ssh/**", "**/.aws/**", "**/.netrc",
				"id_rsa*", "id_ed25519*", "*.pem", "*.key",
				"**/.claude.json", "service-account*.json",
			},
			SecretAllow: []string{"**/.env.example", ".env.example"},
		},
		Waived: map[string]bool{},
	}
}

func TestCheckPathsFileTool(t *testing.T) {
	deny := []string{
		"/home/u/.ssh/id_rsa",
		"/home/u/project/.env",
		"/home/u/project/.env.production",
		"/home/u/.aws/credentials",
		"secrets/server.pem",
		"/home/u/.claude.json",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Read", Paths: []string{p}}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
	ok := []string{"/home/u/project/.env.example", "src/main.go", "README.md"}
	for _, p := range ok {
		tc := ToolCall{Tool: "Read", Paths: []string{p}}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil", p, v)
		}
	}
}

func TestCheckPathsBashReader(t *testing.T) {
	tc := ToolCall{Tool: "Bash", Command: `cat ~/.aws/credentials`}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("cat credentials -> %+v, want deny", v)
	}
	tc = ToolCall{Tool: "Bash", Command: `grep -r TODO src/`}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Errorf("grep src -> %+v, want nil", v)
	}
}
