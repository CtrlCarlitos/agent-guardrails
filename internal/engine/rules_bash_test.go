package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func bashPol() *policy.Policy {
	return &policy.Policy{Slots: policy.Slots{SafeRoots: []string{"/repo/tmp"}}, Waived: map[string]bool{}}
}

func evalBash(t *testing.T, cmd string) *policy.Verdict {
	t.Helper()
	return checkBash(ToolCall{Tool: "Bash", Command: cmd, CWD: "/repo", RepoRoot: "/repo"}, bashPol())
}

func TestCheckBashDestructive(t *testing.T) {
	deny := []string{
		`rm -rf /`,
		`rm -rf ~`,
		`rm -r --force /etc`,
		`rm -fr /var/lib`,
		`dd if=/dev/zero of=/dev/sda`,
		`mkfs.ext4 /dev/sdb1`,
		`wipefs -a /dev/sdc`,
		`shred -u secrets`,
		`ls && rm -rf /`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestCheckBashAllows(t *testing.T) {
	ok := []string{
		`rm file.txt`,
		`rm -rf /repo/tmp/build`,
		`rm -rf ./node_modules`, // inside repo root
		`ls -la`,
		`dd if=in of=out.img`,
	}
	for _, c := range ok {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}
