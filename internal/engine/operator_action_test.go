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
		// Argument parsers are order-agnostic by convention (#126): the same
		// canonical action must be recognised whichever flag comes first, and in
		// the `--flag=value` spelling cmdEgress accepts too.
		{"guardrail egress grant --host api.example.test --scope repo", "web-host-grant", "repo", "api.example.test"},
		{"guardrail egress revoke --host api.example.test,cdn.example.test --scope global", "web-host-revoke", "global", "api.example.test,cdn.example.test"},
		{"guardrail egress grant --scope=repo --host=api.example.test", "web-host-grant", "repo", "api.example.test"},
		{"guardrail egress grant --host=api.example.test --scope=global", "web-host-grant", "global", "api.example.test"},
		{"guardrail egress grant --scope repo --host=api.example.test", "web-host-grant", "repo", "api.example.test"},
		{"guardrail egress grant --scope repo --host https://api.example.test", "", "", ""},
		{"guardrail egress grant --scope repo --host api.example.test:443", "", "", ""},
		{"guardrail egress grant --scope repo --host '*.example.test'", "", "", ""},
		{"guardrail egress grant --scope repo --host API.example.test", "", "", ""},
		{"guardrail egress grant --scope repo --host api.example.test; id", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: tt.command})
			if (ok && action.Name != tt.want) || (!ok && tt.want != "") || action.Parameters["scope"] != tt.scope || action.Parameters["hosts"] != tt.host {
				t.Fatalf("OperatorAction(%q) = (%+v, %v), want %q %q %q", tt.command, action, ok, tt.want, tt.scope, tt.host)
			}
		})
	}
}

func TestOperatorActionAcceptsBatchedEgressHosts(t *testing.T) {
	tc := ToolCall{Tool: "Bash", Command: "guardrail egress grant --scope repo --host api.example.com,cdn.example.com"}
	action, ok := OperatorAction(tc)
	if !ok || action.Name != "web-host-grant" {
		t.Fatalf("action = %+v ok=%v", action, ok)
	}
	if action.Parameters["scope"] != "repo" || action.Parameters["hosts"] != "api.example.com,cdn.example.com" {
		t.Fatalf("parameters = %v", action.Parameters)
	}
}

// Recognising more spellings must not widen what counts as canonical: the
// broker path files an approval request, so anything that is not exactly one
// --scope and one --host, with clean values and no shell syntax, stays a plain
// command under the self-configuration deny (#126).
func TestOperatorActionStillRejectsEverythingThatIsNotExactlyScopeAndHost(t *testing.T) {
	for _, cmd := range []string{
		"guardrail egress grant --scope repo",                                             // missing --host
		"guardrail egress grant --host api.example.test",                                  // missing --scope
		"guardrail egress grant --scope repo --host api.example.test --force",             // unknown flag
		"guardrail egress grant --scope repo --host api.example.test extra",               // stray operand
		"guardrail egress grant --scope repo --scope global --host api.example.test",      // duplicated --scope
		"guardrail egress grant --scope repo --host a.example.test --host b.example.test", // duplicated --host
		"guardrail egress grant --scope=repo --scope=global --host=api.example.test",      // duplicated, = form
		"guardrail egress grant --scope org --host api.example.test",                      // bad scope
		"guardrail egress grant --scope= --host api.example.test",                         // empty scope
		"guardrail egress grant --scope repo --host=",                                     // empty host
		"guardrail egress grant -scope repo -host api.example.test",                       // single-dash spelling
		"guardrail egress grant --scope repo  --host api.example.test",                    // double space
		"guardrail egress grant\t--scope repo --host api.example.test",                    // tab
		" guardrail egress grant --scope repo --host api.example.test",                    // leading space
		"guardrail egress grant --scope repo --host api.example.test ",                    // trailing space
		"guardrail egress grant --host api.example.test --scope repo; id",                 // chained
		"guardrail egress grant --host api.example.test --scope repo && id",               // chained
		"guardrail egress grant --host api.example.test --scope repo | cat",               // piped
		"guardrail egress grant --host api.example.test --scope repo > out",               // redirect
		"guardrail egress grant --host=api.example.test --scope=repo $(id)",               // substitution
		"guardrail egress grant --host $(id).example.test --scope repo",                   // substitution in value
		"guardrail egress grant --host `id`.example.test --scope repo",                    // backticks
		"guardrail egress grant --host 'api.example.test' --scope repo",                   // quoted value
		"guardrail egress grant --host api.example.test --scope \"repo\"",                 // quoted value
		"guardrail egress grant --host=api.example.test,BAD --scope repo",                 // bad host in batch
		"guardrail egress grant --host=api.example.test, --scope=repo",                    // trailing comma
		"guardrail egress list --host api.example.test --scope repo",                      // not grant/revoke
		"guardrail egress grant --host api.example.test --scope repo\nid",                 // newline
		"guardrail egress grant --host=api.example.test=x --scope repo",                   // second '='
		"guardrail egress grant --scope --host api.example.test",                          // flag eaten as value
	} {
		if action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: cmd}); ok {
			t.Errorf("command accepted as %+v: %q", action, cmd)
		}
	}
}

func TestOperatorActionRejectsMalformedHostBatches(t *testing.T) {
	for _, cmd := range []string{
		"guardrail egress grant --scope repo --host api.example.com,",
		"guardrail egress grant --scope repo --host ,cdn.example.com",
		"guardrail egress grant --scope repo --host api.example.com,,cdn.example.com",
		"guardrail egress grant --scope repo --host api.example.com,BAD",
		"guardrail egress revoke --scope global --host api.example.com,",
	} {
		if _, ok := OperatorAction(ToolCall{Tool: "Bash", Command: cmd}); ok {
			t.Errorf("command accepted: %q", cmd)
		}
	}
}
