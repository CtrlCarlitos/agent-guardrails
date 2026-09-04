package engine

import (
	"path"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

var pathReaders = map[string]bool{
	"cat": true, "head": true, "tail": true, "grep": true, "egrep": true, "fgrep": true,
	"sed": true, "awk": true, "less": true, "more": true, "bat": true, "xxd": true,
	"od": true, "strings": true,
}

func isFileTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "read", "edit", "write", "multiedit":
		return true
	}
	return false
}

func checkPaths(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	var candidates []string
	if isFileTool(tc.Tool) {
		candidates = append(candidates, tc.Paths...)
	}
	if tc.IsBash() {
		simples, err := Normalize(tc.Command)
		if err == nil {
			for _, s := range simples {
				if len(s.Argv) > 0 && pathReaders[s.Argv[0]] {
					candidates = append(candidates, nonFlagArgs(s.Argv)...)
				}
			}
		}
	}
	for _, c := range candidates {
		c = strings.TrimPrefix(c, "~/")
		c = strings.TrimPrefix(c, "~")
		if matchesAnyGlob(c, pol.Slots.SecretAllow) {
			continue
		}
		if matchesAnyGlob(c, pol.Slots.SecretGlobs) {
			if pol.Waived["P4.secret-path"] {
				return nil
			}
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P4.secret-path",
				Reason: "access to a credential/secret path: " + c}
		}
	}
	return nil
}

func matchesAnyGlob(p string, globs []string) bool {
	p = strings.TrimPrefix(p, "./")
	base := path.Base(p)
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, p); ok {
			return true
		}
		if ok, _ := doublestar.Match(g, base); ok {
			return true
		}
	}
	return false
}
