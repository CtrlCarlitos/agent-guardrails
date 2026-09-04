package engine

import (
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func checkBash(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	if !tc.IsBash() {
		return nil
	}
	simples, err := Normalize(tc.Command)
	if err != nil {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "tokenize-failed",
			Reason: "could not parse shell command; failing closed to ask"}
	}
	var worst *policy.Verdict
	take := func(v *policy.Verdict) {
		if v == nil {
			return
		}
		if pol.Waived[v.RuleID] {
			return
		}
		if worst == nil || v.Decision.Severity() > worst.Decision.Severity() {
			worst = v
		}
	}
	for _, s := range simples {
		if len(s.Argv) == 0 {
			continue
		}
		take(checkRmRf(s, tc, pol))
		take(checkDiskDestroyers(s))
	}
	return worst
}

func hasAnyFlag(argv []string, short string, long ...string) bool {
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "--") {
			for _, l := range long {
				if a == l {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if strings.ContainsAny(a[1:], short) {
				return true
			}
		}
	}
	return false
}

func nonFlagArgs(argv []string) []string {
	var out []string
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func checkRmRf(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	if s.Argv[0] != "rm" {
		return nil
	}
	if !hasAnyFlag(s.Argv, "rf", "--recursive", "--force", "-R") {
		// need at least one of recursive OR force to be dangerous
		return nil
	}
	recursive := hasAnyFlag(s.Argv, "rR", "--recursive")
	force := hasAnyFlag(s.Argv, "f", "--force")
	if !recursive && !force {
		return nil
	}
	for _, raw := range nonFlagArgs(s.Argv) {
		if !withinSafe(resolvePath(raw, tc.CWD), tc.RepoRoot, pol.Slots.SafeRoots) {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf",
				Reason: "recursive/forced rm of a path outside the repo and configured safe roots: " + raw}
		}
	}
	return nil
}

func checkDiskDestroyers(s Simple) *policy.Verdict {
	head := s.Argv[0]
	switch {
	case head == "dd":
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "of=/dev/") {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.dd",
					Reason: "dd writing to a raw device: " + a}
			}
		}
	case head == "mkfs" || strings.HasPrefix(head, "mkfs.") || head == "mke2fs" || head == "wipefs":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.mkfs",
			Reason: "filesystem-destroying command: " + head}
	case head == "shred" || head == "srm":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.shred",
			Reason: "irreversible secure-delete command: " + head}
	}
	return nil
}

func resolvePath(p, cwd string) string {
	if strings.HasPrefix(p, "~") {
		return p // treat "~" as outside any safe root; do not expand
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(cwd, p))
}

func withinSafe(target, repoRoot string, safeRoots []string) bool {
	if target == "~" || strings.HasPrefix(target, "~/") || target == "/" {
		return false
	}
	roots := append([]string{repoRoot}, safeRoots...)
	for _, r := range roots {
		if r == "" {
			continue
		}
		rr := filepath.Clean(r)
		if target == rr || strings.HasPrefix(target, rr+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
