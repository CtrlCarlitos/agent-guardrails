package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalLaunch(t *testing.T, cmd string) policy.Verdict {
	t.Helper()
	root := repoRootForHost()
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: cmd, CWD: root, RepoRoot: root}, envPol())
}

func wantUnsupervisedDeny(t *testing.T, commands []string) {
	t.Helper()
	for _, cmd := range commands {
		v := evalLaunch(t, cmd)
		if v.Decision != policy.Deny || v.RuleID != UnsupervisedChildRule {
			t.Errorf("%q: got %s %s (%s), want deny %s", cmd, v.Decision, v.RuleID, v.Reason, UnsupervisedChildRule)
			continue
		}
		if !strings.Contains(v.Reason, "child agent session") {
			t.Errorf("%q: reason %q does not say what was denied", cmd, v.Reason)
		}
	}
}

// A session can start another agent host from its shell. The child loads the
// same user settings and so runs the same Guardrail hook, unless the command
// that starts it says otherwise. Each of these starts a child the hook does
// not supervise, and each was allowed: the rule that keeps an agent from
// editing its own hook configuration did not look at a command that turns the
// hook off for a child.
func TestAgentLaunchWithHookDisablingFlagsIsDenied(t *testing.T) {
	wantUnsupervisedDeny(t, []string{
		// Claude Code: flags that skip hooks or the user settings holding them.
		`claude -p --settings '{"disableAllHooks": true}' "list files"`,
		`claude --settings '{"disableAllHooks":true}' -p "list files"`,
		`claude -p --settings '{"env":{"PATH":"/nonexistent"}}' "list files"`,
		`claude -p --settings=off.json "list files"`,
		`claude -p --settings off.json "list files"`,
		`claude -p --settings '[]' "list files"`,
		`claude --bare -p "list files"`,
		`claude -p "list files" --bare`,
		`claude --restricted -p "read .env"`,
		`claude -p --setting-sources project "list files"`,
		`claude -p --setting-sources=project,local "list files"`,
		// Codex: configuration overrides.
		`codex exec --ignore-user-config "list files"`,
		`codex exec -c features.hooks=false "list files"`,
		`codex exec -cfeatures.hooks=false "list files"`,
		`codex --config hooks=false exec "list files"`,
		`codex exec --profile bare "list files"`,
		`codex exec -p bare "list files"`,
		`codex exec --disable codex_hooks "list files"`,
		// Antigravity: session settings.
		`agy -p "list files" --settings '{"hooks": false}'`,
		// A flag assembled by the shell is still the flag.
		`claude -p x --bar{e,e}`,
		`claude -p x --bare{,}`,
		`F=--bare; claude -p x $F`,
	})
}

// The host is the same program however it is named or started.
func TestAgentLaunchIsRecognisedThroughShimsRunnersAndLaunchers(t *testing.T) {
	wantUnsupervisedDeny(t, []string{
		`claude.exe --bare -p "list files"`,
		`C:\Users\u\.local\bin\claude.exe --bare -p x`,
		`claude.cmd --bare -p x`,
		`claude.ps1 --bare -p x`,
		`C:\Users\u\AppData\Roaming\npm\claude.cmd --bare -p x`,
		`node_modules/.bin/claude.cmd --bare -p x`,
		`codex.cmd exec --ignore-user-config "list files"`,
		`npx @anthropic-ai/claude-code --bare -p "list files"`,
		`npx -y @openai/codex exec --ignore-user-config "list files"`,
		`npx.cmd @anthropic-ai/claude-code --bare -p x`,
		`pnpm exec claude --bare -p x`,
		`node node_modules/@anthropic-ai/claude-code/cli.js --bare -p x`,
		`nohup claude --bare -p x`,
		`cmd /c claude --bare -p x`,
		`cmd /c claude.cmd --bare -p x`,
		`bash -c "claude --bare -p x"`,
		`pwsh -c "claude --bare -p x"`,
		`powershell.exe -NoProfile -Command "claude --bare -p x"`,
		`Start-Process claude -ArgumentList '--bare','-p','x'`,
		`Start-Process claude '--bare -p x'`,
		`start claude --bare -p x`,
		`wsl claude --bare -p x`,
		`tmux new -d claude --bare -p x`,
	})
}

// A host finds its settings, and the hook finds guardrail, through the
// environment. Giving the child another one moves it away from both.
func TestAgentLaunchWithARedirectedEnvironmentIsDenied(t *testing.T) {
	wantUnsupervisedDeny(t, []string{
		`HOME=/tmp/x claude -p "list files"`,
		`HOME+=/nonexistent claude -p x`,
		`USERPROFILE=C:/tmp/x claude -p "list files"`,
		`CLAUDE_CONFIG_DIR=/tmp/x claude -p "list files"`,
		`CLAUDE_CODE_SIMPLE=1 claude -p "list files"`,
		`PATH=/usr/bin:/bin claude -p x`,
		`CODEX_HOME=/tmp/x codex exec "list files"`,
		`XDG_CONFIG_HOME=/tmp/x opencode run "list files"`,
		`XDG_STATE_HOME=/tmp/x claude -p x`,
		`OPENCODE_CONFIG=/tmp/x.json opencode run "list files"`,
		`ANTIGRAVITY_APP_DATA_DIR=/tmp/x agy -p x`,
		`GUARDRAIL_CONFIG=/tmp/p.toml claude -p x`,
		`env HOME=/tmp/x claude -p "list files"`,
		`env "HOME"=/tmp/x claude -p x`,
		`env PATH=/usr/bin claude -p x`,
		`env -i claude -p "list files"`,
		`env - claude -p x`,
		`env -u HOME claude -p "list files"`,
		`export HOME=/tmp/x; claude -p "list files"`,
		`export HOME+=/x; claude -p x`,
		`export "HO""ME"=/tmp/x; claude -p x`,
		`H=HOME; export $H=/tmp/x; claude -p x`,
		`export CLAUDE_CONFIG_DIR=/tmp/x && claude -p "list files"`,
		`HOME=/tmp/x; claude -p x`,
		`unset CLAUDE_CONFIG_DIR; claude -p x`,
		`printf -v HOME %s /tmp/x; claude -p x`,
		`read HOME <<< /tmp/x; claude -p x`,
		`set HOME=x && claude -p y`,
		`bash -c "HOME=/tmp/x claude -p x"`,
		// PowerShell's environment drive.
		`$env:HOME='x'; claude -p y`,
		`Set-Item env:USERPROFILE C:\tmp\x; claude -p y`,
		`Set-Item -Path Env:USERPROFILE -Value C:\tmp\x; claude -p y`,
		`New-Item -Path Env:CLAUDE_CONFIG_DIR -Value C:\tmp\x; claude -p y`,
		`Set-Content env:CLAUDE_CONFIG_DIR C:\tmp\x; claude -p y`,
	})
}

// A child started the ordinary way loads the user settings and the hook with
// them, so it stays allowed.
func TestOrdinaryAgentLaunchStaysAllowed(t *testing.T) {
	for _, cmd := range []string{
		`claude -p "list files"`,
		`claude -p "list files" --output-format json --max-turns 3`,
		`claude -p --setting-sources user,project "list files"`,
		`claude -p --settings '{"model": "sonnet"}' "list files"`,
		`claude --settings '{"permissions":{"allow":["Read"]}}' -p x`,
		`claude -p "x" --model=sonnet`,
		`claude -c`,
		`claude --version`,
		`claude doctor`,
		`codex exec "list files"`,
		`codex exec -c model_reasoning_effort=high "list files"`,
		`codex exec -c model=gpt-5 "x"`,
		`codex exec -m gpt-5 "x"`,
		`codex exec -C /repo "x"`,
		`codex --version`,
		`opencode run "list files"`,
		`opencode -c`,
		`agy -p "list files"`,
		`JAVA_HOME=/opt/jdk claude -p x`,
		`MY_APPDATA=/x claude -p x`,
	} {
		if v := evalLaunch(t, cmd); v.Decision != policy.Allow {
			t.Errorf("%q: got %s %s (%s), want allow", cmd, v.Decision, v.RuleID, v.Reason)
		}
	}
}

// Text that mentions a flag or a variable is not a launch with it: a prompt,
// a commit message, a search, another command's own environment, or what
// follows `--`.
func TestMentionsOfFlagsAndVariablesAreNotLaunches(t *testing.T) {
	for _, cmd := range []string{
		`claude -p "explain what --bare does"`,
		`claude -p --append-system-prompt "never use --bare" x`,
		`claude -p "set HOME=/app in the Dockerfile and rebuild"`,
		`claude -p "explain what CLAUDE_CONFIG_DIR= does"`,
		`claude -p 'fix the Makefile line: export HOME=$(PWD)/.home'`,
		`claude -p "why does env -i break my script?"`,
		`claude -p x --allowedTools "Bash(env -i:*)"`,
		`claude -p x -- --bare`,
		`claude mcp add srv -- npx -y srv --bare`,
		`claude mcp add srv -e API_HOME=/x -- npx srv`,
		`codex exec "explain -c and --profile"`,
		`agy -p "tell me about --settings"`,
		`echo claude --bare`,
		`echo "HOME=/x claude --bare"`,
		`echo "HOME=$HOME" && claude -p "list files"`,
		`git commit -m "claude --bare is denied now"`,
		`git commit -m "docs: HOME=/x example" && claude -p "review the last commit"`,
		`git log --grep "claude --bare"`,
		`grep -r "disableAllHooks" docs`,
		`rg "CLAUDE_CONFIG_DIR=" .`,
		`HOME=/tmp/x go test ./...`,
		`env HOME=/tmp/x make test`,
		`HOME=/tmp/x go test ./... && claude -p "summarize the test output"`,
		`docker run -e HOME=/root img; claude -p x`,
		`cd codex`,
		`which claude`,
	} {
		if v := evalLaunch(t, cmd); v.RuleID == UnsupervisedChildRule {
			t.Errorf("%q: got %s %s (%s), want no %s verdict", cmd, v.Decision, v.RuleID, v.Reason, UnsupervisedChildRule)
		}
	}
}

// The rule has its own ID. An operator who waives P5.self-config to let a
// session edit CLAUDE.md has not agreed to unsupervised children.
func TestUnsupervisedChildIsNotWaivedWithSelfConfig(t *testing.T) {
	root := repoRootForHost()
	pol := envPol()
	pol.Waived = map[string]bool{"P5.self-config": true}
	v := Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: `claude --bare -p x`, CWD: root, RepoRoot: root}, pol)
	if v.Decision != policy.Deny || v.RuleID != UnsupervisedChildRule {
		t.Errorf("with P5.self-config waived: got %s %s, want deny %s", v.Decision, v.RuleID, UnsupervisedChildRule)
	}
}
