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
		`rm -R /etc`,
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
		`git push origin main`,
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
