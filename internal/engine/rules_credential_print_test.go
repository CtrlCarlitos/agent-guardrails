package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #436, operator decision 2026-09-28: everything a command prints is sent to
// the model provider, so a credential-printing command may run only when its
// output is captured by `$(...)` and handed to a command that does not print
// it (or piped into a credential consumer). Measured on 7018c7b, every
// command below allowed except the gcloud forms, which asked under the wrong
// rule.

func evalCredentialPrint(t *testing.T, tool, command string) policy.Verdict {
	t.Helper()
	return Evaluate(ToolCall{Plane: "claude", Tool: tool, NativeTool: tool,
		Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
}

// assertCredentialPrintAsks wants the call to ask and the new rule to fire on
// one of its commands. Where another ask fired first on an earlier command
// (P3.unresolved on `cat <(...)`, say) the verdict is the same ask and the
// audit names that rule; the credential rule must still be what the
// credential-printing command itself gets.
func assertCredentialPrintAsks(t *testing.T, tool string, commands ...string) {
	t.Helper()
	for _, command := range commands {
		v := evalCredentialPrint(t, tool, command)
		if v.Decision.Severity() < policy.Ask.Severity() {
			t.Errorf("%s %q -> %s/%s, want ask/P4.credential-print", tool, command, v.Decision, v.RuleID)
			continue
		}
		if v.RuleID != "P4.credential-print" && !credentialPrintRaised(t, tool, command) {
			t.Errorf("%s %q -> %s/%s, and P4.credential-print did not fire on any of its commands", tool, command, v.Decision, v.RuleID)
		}
	}
}

func credentialPrintRaised(t *testing.T, tool, command string) bool {
	t.Helper()
	analysis := analyzeBash(ToolCall{Plane: "claude", Tool: tool, NativeTool: tool,
		Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"})
	for _, s := range analysis.orderedSimples {
		if checkCredentialPrint(s) != nil {
			return true
		}
	}
	return false
}

func assertCredentialPrintAllows(t *testing.T, tool string, commands ...string) {
	t.Helper()
	for _, command := range commands {
		if v := evalCredentialPrint(t, tool, command); v.Decision != policy.Allow {
			t.Errorf("%s %q -> %s/%s (%s), want allow", tool, command, v.Decision, v.RuleID, v.Reason)
		}
	}
}

func TestCredentialPrintingCommandsAskWhenTheirOutputReachesTheSession(t *testing.T) {
	assertCredentialPrintAsks(t, "Bash",
		"gh auth token",
		"gh.exe auth token",
		"gh auth token --hostname github.com",
		"gh auth status -t",
		"gh auth status --show-token",
		"gh auth git-credential get",
		"printf 'protocol=https\\nhost=github.com\\n' | git credential fill",
		"git credential fill < req.txt",
		"git credential-manager get",
		"git-credential-manager get",
		"security find-generic-password -s x -w",
		"security find-internet-password -s github.com -g",
		"secret-tool lookup service gh",
		"docker-credential-desktop list",
		"docker-credential-desktop.exe get",
		"az account get-access-token",
		"az account get-access-token --query accessToken -o tsv",
		"aws configure get aws_secret_access_key",
		"aws sts get-session-token",
		"aws ecr get-login-password",
		"aws secretsmanager get-secret-value --secret-id x",
		"kubectl config view --raw",
		"npm config get //registry.npmjs.org/:_authToken",
		"gcloud auth print-access-token",
		"gcloud auth print-identity-token",
		"gcloud auth application-default print-access-token",
		"op read op://vault/item/field",
		"vault kv get secret/x",
		"timeout 5 gh auth token",
		"env GH_HOST=x gh auth token",
		"bash -c 'gh auth token'",
		"cmd /c gh auth token",
	)
}

// The shapes that put the value in front of the session after all.
func TestCredentialPrintingCommandsAskWhenTheSubstitutionPrints(t *testing.T) {
	assertCredentialPrintAsks(t, "Bash",
		"echo $(gh auth token)",
		"echo \"$(gh auth token)\"",
		"printf '%s\\n' \"$(gh auth token)\"",
		"echo `gh auth token`",
		"timeout 5 echo $(gh auth token)",
		"cat <<< \"$(gh auth token)\"",
		"cat <(gh auth token)",
		"GH_TOKEN=$(gh auth token) env",
		"GH_TOKEN=$(gh auth token) printenv GH_TOKEN",
		"GH_TOKEN=$(gh auth token) tee out.txt",
		// A plain variable outlives the capture under a name nobody reads
		// as secret; the prefix form is the one that stays contained.
		"TOKEN=$(gh auth token)",
		"TOKEN=$(gh auth token); ./tool \"$TOKEN\"",
		"export GH_TOKEN=$(gh auth token)",
		// Written somewhere the next command can read it back.
		"gh auth token > t.txt",
		"gh auth token >> t.txt",
		"gh auth token >&2",
		// A pipe into anything that is not a credential consumer.
		"gh auth token | cat",
		"gh auth token | tee t.txt",
		"gh auth token | xargs",
		"gh auth token | xargs echo",
		"gh auth token | tr -d '\\n'",
		// The substituted value is the command name, or code.
		"$(gh auth token)",
		"bash -c \"echo $(gh auth token)\"",
		"python -c \"print('$(gh auth token)')\"",
		"bash <<< \"$(gh auth token)\"",
		// xtrace prints every expanded command line.
		"set -x; GH_TOKEN=$(gh auth token) ./tool",
		"set -euxo pipefail; ./tool --token \"$(gh auth token)\"",
		"bash -x -c 'GH_TOKEN=$(gh auth token) ./tool'",
		"GH_TOKEN=$(gh auth token) bash -x ./script.sh",
		// The body of `bash -c` prints into the session unless the outer
		// command captures it.
		"echo $(bash -c 'gh auth token')",
	)
}

func TestCredentialPrintingCommandsAllowWhenCapturedForAnotherCommand(t *testing.T) {
	assertCredentialPrintAllows(t, "Bash",
		"GH_TOKEN=$(gh auth token) ./tool",
		"GH_TOKEN=\"$(gh auth token)\" gh pr list",
		"GH_TOKEN=$(gh auth token) GH_HOST=github.com ./tool --flag",
		"docker login ghcr.io -u me --password-stdin <<< \"$(gh auth token)\"",
		"gh auth token | docker login ghcr.io -u me --password-stdin",
		"gh.exe auth token | docker login ghcr.io -u me --password-stdin",
		"gh auth token | tr -d '\\n' | docker login ghcr.io -u me --password-stdin",
		"aws ecr get-login-password | docker login --username AWS --password-stdin 1.dkr.ecr.us-east-1.amazonaws.com",
		"gh auth token > /dev/null",
		"KUBECONFIG_DATA=$(kubectl config view --raw) ./deploy",
		"AZ_TOKEN=$(az account get-access-token --query accessToken -o tsv) ./tool",
		"CLOUDSDK_AUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) ./tool",
		"GH_TOKEN=$(bash -c 'gh auth token') ./tool",
		"GH_TOKEN=$(gh auth token | tr -d '\\n') ./tool",
		"GH_TOKEN=$(gh auth token) bash ./script.sh",
	)
	// As an argument of a program whose operands the Engine does not know,
	// a substitution already asks P3.unresolved (unchanged here); the new
	// rule must not be what stops it.
	assertCredentialPrintNotRaised(t, "Bash",
		"./tool --token \"$(gh auth token)\"",
		"./tool --token=$(gh auth token)",
		"timeout 30 ./tool --token \"$(gh auth token)\"",
		"docker login ghcr.io -u me --password-stdin < <(gh auth token)",
		"./tool --token \"$GITHUB_TOKEN\"",
	)
}

func assertCredentialPrintNotRaised(t *testing.T, tool string, commands ...string) {
	t.Helper()
	for _, command := range commands {
		if v := evalCredentialPrint(t, tool, command); v.RuleID == "P4.credential-print" {
			t.Errorf("%s %q -> %s/%s, want no P4.credential-print", tool, command, v.Decision, v.RuleID)
		}
	}
}

// The read twins stay allowed: they print configuration or identity, not the
// secret.
func TestCredentialAdjacentReadsStayAllowed(t *testing.T) {
	assertCredentialPrintAllows(t, "Bash",
		"gh auth status",
		"gh auth status --hostname github.com",
		"security find-generic-password -s x",
		"aws configure get region",
		"aws sts get-caller-identity",
		"kubectl config view",
		"kubectl config view --minify",
		"npm config get registry",
		"az account show",
		"gcloud auth list",
		"printenv HOME",
		"printenv PATH HOME",
		"echo $HOME",
		"echo '$GITHUB_TOKEN'",
		"env FOO=1 ./tool",
		"set -e",
	)
}

func TestSecretEnvironmentReadsAsk(t *testing.T) {
	assertCredentialPrintAsks(t, "Bash",
		"env",
		"env -0",
		"printenv",
		"printenv GITHUB_TOKEN",
		"printenv HOME GH_TOKEN",
		"echo $GITHUB_TOKEN",
		"echo \"${GITHUB_TOKEN}\"",
		"echo $github_token",
		"echo \"token: $NPM_TOKEN\"",
		"printf '%s' \"$NPM_API_KEY\"",
		"echo $DB_PASSWORD",
		"echo $MYSQL_PASSWD",
		"echo $SSH_PRIVATE_KEY",
		"echo $GOOGLE_APPLICATION_CREDENTIALS",
		"echo $CLIENT_SECRET > secret.txt",
		"env | grep TOKEN",
		"set",
	)
	// Handed to a program that does not print it, the reference is the
	// intended use.
	assertCredentialPrintAllows(t, "Bash",
		"GH_TOKEN=$GITHUB_TOKEN ./tool",
		"echo $GITHUB_TOKEN | docker login ghcr.io -u me --password-stdin",
		"printenv GITHUB_TOKEN | docker login ghcr.io -u me --password-stdin",
		"GH_TOKEN=$(printenv GITHUB_TOKEN) ./tool",
	)
}

func TestCredentialPrintPowerShellForms(t *testing.T) {
	assertCredentialPrintAsks(t, "PowerShell",
		"gh auth token",
		"gh.exe auth token",
		"Get-ChildItem env:",
		"Get-ChildItem Env:\\",
		"gci env:",
		"dir env:",
		"ls env:",
		"Get-ChildItem env:GITHUB_TOKEN",
		"Get-Item env:GH_TOKEN",
		"Get-Content env:GITHUB_TOKEN",
		"echo $env:GITHUB_TOKEN",
		"Write-Output $env:GITHUB_TOKEN",
		"Write-Host $env:GITHUB_TOKEN",
		"Write-Host \"token $env:GITHUB_TOKEN\"",
		"Get-Secret -Name gh -AsPlainText",
	)
	assertCredentialPrintAllows(t, "PowerShell",
		"echo $env:PATH",
		"Get-ChildItem env:PATH",
		"gh.exe auth token | docker login ghcr.io -u me --password-stdin",
	)
}

// The gcloud token printers asked before, but under P6.cloud-mutate, whose
// reason ("not a known read operation on a metered cloud account") is wrong
// for them. They belong to the new rule and follow its capture exemption.
func TestGcloudPrintTokenUsesTheCredentialPrintRule(t *testing.T) {
	for _, command := range []string{
		"gcloud auth print-access-token",
		"gcloud auth print-identity-token --audiences=x",
	} {
		v := evalCredentialPrint(t, "Bash", command)
		if v.RuleID != "P4.credential-print" {
			t.Errorf("%q -> %s/%s, want P4.credential-print", command, v.Decision, v.RuleID)
		}
	}
	// A real mutation keeps its own rule.
	if v := evalCredentialPrint(t, "Bash", "gcloud compute instances delete vm"); v.RuleID != "P6.cloud-mutate" {
		t.Errorf("gcloud compute instances delete -> %s/%s, want P6.cloud-mutate", v.Decision, v.RuleID)
	}
}

// The reason must give the next step (docs/error-message-discipline.md).
func TestCredentialPrintReasonSaysHowToPassTheValue(t *testing.T) {
	v := evalCredentialPrint(t, "Bash", "gh auth token")
	for _, want := range []string{"model provider", "$(gh auth token)", "--password-stdin"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("reason %q does not mention %q", v.Reason, want)
		}
	}
}
