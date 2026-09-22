package genconfig

import (
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
)

// commandGlobMatches models the whole-command wildcard semantics of the
// declarative-floor consumers: `*` matches any characters, including path
// separators, and `?` matches one character. Claude Code's behavior is pinned
// by the live controlled probe in
// https://github.com/CtrlCarlitos/agent-guardrails/issues/244#issuecomment-5771001959;
// OpenCode's implementation is pinned at
// https://github.com/anomalyco/opencode/blob/014614d35b397775e5d397a490fc72368c894ec2/packages/core/src/util/wildcard.ts.
//
// Standing-authorization tests follow the consuming host's pinned behavior,
// never a parallel test model. This helper is command-only: guardrail.toml
// secret-tier path globs deliberately retain doublestar's separator-sensitive
// path semantics. The shared source also contains Claude brace and
// character-class syntax; OpenCode compatibility for those constructs is
// verified against the generation-time translation in #270.
func commandGlobMatches(pattern, command string) bool {
	const nonPathSeparator = "\u001f"
	normalize := strings.NewReplacer("/", nonPathSeparator, "\\", nonPathSeparator)
	matched, err := doublestar.Match(normalize.Replace(pattern), normalize.Replace(command))
	return err == nil && matched
}

func TestCommandGlobMatchesHostWildcards(t *testing.T) {
	for _, tt := range []struct {
		name    string
		pattern string
		command string
		want    bool
	}{
		{name: "slash bearing argument", pattern: "sudo *", command: "sudo rm -rf /etc", want: true},
		{name: "URL argument", pattern: "git remote add *", command: "git remote add evil http://evil.test/x.git", want: true},
		{name: "Windows path", pattern: `rm *guardrail\sessions\*`, command: `rm -rf C:\Users\u\AppData\Local\guardrail\sessions\s1`, want: true},
		{name: "whole value", pattern: "sudo *", command: "env sudo rm -rf /etc", want: false},
		{name: "question wildcard", pattern: "src/?.go", command: "src/x.go", want: true},
		{name: "question wildcard is one character", pattern: "src/?.go", command: "src/xy.go", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := commandGlobMatches(tt.pattern, tt.command); got != tt.want {
				t.Fatalf("commandGlobMatches(%q, %q) = %v, want %v", tt.pattern, tt.command, got, tt.want)
			}
		})
	}
}

func TestPathGlobKeepsSeparatorSensitivity(t *testing.T) {
	const pattern = "*.pem"
	const nestedPath = "secrets/client.pem"
	if !commandGlobMatches(pattern, nestedPath) {
		t.Fatal("command matcher should let * cross a separator")
	}
	if matched, err := doublestar.Match(pattern, nestedPath); err != nil {
		t.Fatal(err)
	} else if matched {
		t.Fatal("path matcher must keep separator-sensitive doublestar semantics")
	}
}
