// Package genconfig translates a merged policy into each plane's native
// declarative config (the "declarative floor") and merges it into that plane's
// settings file.
package genconfig

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

// Fragment is a JSON-shaped config fragment ready to be merged into a plane's
// settings file.
type Fragment = map[string]any

// bashDenyGlobs is the curated coarse floor for P1 deny-tier shell commands.
// Intentionally not exhaustive — Claude's argument-glob matching is fragile and
// the Engine is the real check; this only has to catch the worst cases when the
// Engine binary is missing.
func bashDenyGlobs() []string {
	base := []string{
		"Bash(rm -rf /)", "Bash(rm -rf ~)", "Bash(rm -rf .)", "Bash(rm -rf ..)",
		"Bash(rm -fr /)", "Bash(rm -fr ~)", "Bash(rm -fr .)", "Bash(rm -fr ..)",
		"Bash(rm -r -f /)", "Bash(rm -r -f ~)", "Bash(rm -r -f .)", "Bash(rm -r -f ..)",
		"Bash(rm -f -r /)", "Bash(rm -f -r ~)", "Bash(rm -f -r .)", "Bash(rm -f -r ..)",
		"Bash(dd *)",
		"Bash(mkfs*)", "Bash(wipefs *)",
		"Bash(shred *)", "Bash(srm *)",
		"Bash(sudo *)", "Bash(su *)", "Bash(su)", "Bash(doas *)",
		"Bash(git push --force*)", "Bash(git push -f*)",
		"Bash(git clean -f*)", "Bash(git clean -xf*)", "Bash(git clean -fx*)",
		"Bash(git clean -df*)", "Bash(git clean -fd*)",
		"Bash(git reset --hard*)", "Bash(git reset --keep*)",
		"Bash(git config core.hooksPath *)", "Bash(git config core.hooksPath /**)",
		"Bash(git config core.fsmonitor *)", "Bash(git config core.fsmonitor /**)",
		"Bash(git config core.sshCommand *)", "Bash(git config core.sshCommand /**)",
		"Bash(git config core.pager *)", "Bash(git config core.pager /**)",
		"Bash(git config core.editor *)", "Bash(git config core.editor /**)",
		"Bash(git config credential.* *)", "Bash(git config credential.* /**)",
		"Bash(git config include.path *)", "Bash(git config include.path /**)",
		"Bash(git config includeIf.* *)", "Bash(git config includeIf.* /**)",
		"Bash(git config alias.* *)", "Bash(git config alias.* /**)",
		"Bash(git filter-branch*)", "Bash(git filter-repo*)",
		"Bash(pip install --index-url*)", "Bash(pip3 install --index-url*)",
		"Bash(npm install --registry*)",
		"Bash(docker compose down*)",
		"Bash(docker system prune*)", "Bash(docker volume prune*)", "Bash(docker network prune*)",
		"Bash(rm *guardrail/sessions/*)", `Bash(rm *guardrail\sessions\*)`,
	}
	// Appended here, not at a plane's assembly point, so both planes inherit
	// them from one source: OpencodeConfig rewrites exactly this function and
	// bashAskGlobs, so a glob added downstream would be a silent one-plane floor.
	return append(base, ghDenyGlobs()...)
}

// ghAskGlobs and ghDenyGlobs mediate the GitHub CLI.
//
// `gh` is a shell command that mutates state nobody can see in the working
// tree: it merges pull requests, cuts and deletes releases, dispatches
// workflows and deletes repositories. None of that was on the floor, so with
// the Engine unreachable (ADR-0022) those ran unmediated. Reads stay allow —
// `gh` is how the fleet checks CI, and prompting on every view trains people
// to click through the prompts that matter.
//
// The `{,**}` spellings are Claude's source grammar. Both hosts make `*` cross
// separators, but OpenCode treats braces literally, so OpencodeConfig lowers
// these patterns into its narrower grammar at generation time (#270).
func ghAskGlobs() []string {
	return []string{
		"Bash(gh pr merge{,**})",
		"Bash(gh release create{,**})",
		"Bash(gh release delete{,**})",
		"Bash(gh workflow run{,**})",
		// `gh api` is only partly expressible here, and the limit is stated
		// rather than papered over: a glob can match a method flag written
		// *before* the endpoint, but cannot reorder tokens or infer an implicit
		// POST. Endpoint-first forms such as `gh api repos/o/r -X POST`, plus
		// `-f`/`--input` spellings, stay with the Engine (#228) instead of being
		// faked by a glob that would also match reads.
		"Bash(gh api -X {,**})",
		"Bash(gh api --method {,**})",

		// Porcelain equivalents (#228). These reach the same endpoints the
		// parser watches, without any method flag to parse: `gh secret set`
		// is a PUT to actions/secrets, `gh repo edit --visibility` a PATCH on
		// the repo. They are shape-level, which is what a glob can actually
		// match, so this is the right layer for them.
		//
		// Both verbs of a pair are listed on purpose. An ask on `secret set`
		// alone is evadable by reaching for `secret delete`, and "break CI by
		// removing the token" is the same authority as "hand CI a token".
		"Bash(gh secret set{,**})",
		"Bash(gh secret delete{,**})",
		"Bash(gh variable set{,**})",
		"Bash(gh variable delete{,**})",

		// Repository-level acts under the operator's admin authority.
		// `gh repo delete` denies (below); these ask because the blast radius
		// is smaller but the authority is identical.
		"Bash(gh repo edit{,**})",
		"Bash(gh repo archive{,**})",
		"Bash(gh repo rename{,**})",
		"Bash(gh repo transfer{,**})",

		// Changing which authority is in play. These mutate no repository at
		// all -- they change who the agent *is*, and a second logged-in
		// account (an employer's, say) is one command away from a session that
		// started in a personal project.
		"Bash(gh auth switch{,**})",
		"Bash(gh auth login{,**})",
		"Bash(gh auth refresh{,**})",
		"Bash(gh auth logout{,**})",
		// Account-level persistence that outlives a token rotation.
		"Bash(gh ssh-key add{,**})",
		"Bash(gh gpg-key add{,**})",

		// A published artifact set, the companion to `gh release create`.
		"Bash(gh release edit{,**})",
		"Bash(gh release upload{,**})",
	}
}

func ghDenyGlobs() []string {
	return []string{
		"Bash(gh repo delete{,**})",
	}
}

// bashAskGlobs is the curated coarse floor for P1 ask-tier shell commands.
func bashAskGlobs() []string {
	base := []string{
		"Bash(chmod -R *)", "Bash(chmod 777 *)", "Bash(chmod -R 777 *)",
		"Bash(chown -R *)",
		"Bash(truncate *)",
		"Bash(kill -9 *)", "Bash(killall *)", "Bash(pkill *)",
		"Bash(git checkout .)", "Bash(git restore .)",
		"Bash(git branch -D *)", "Bash(git commit --amend*)",
		"Bash(git remote add *)", "Bash(git remote set-url *)",
		"Bash(git stash clear)", "Bash(git stash drop*)",
		"Bash(git push * main)", "Bash(git push * master)", "Bash(git push --tags*)",
		// Backstop for #218. The Engine classifies a tag destination properly;
		// this is the floor's best effort for when the Engine is unreachable
		// (ADR-0022). It is crude by construction: a glob cannot tell a tag
		// from a branch, so it also asks for a branch literally named v1.2.3.
		"Bash(git push * v[0-9]*)",
		"Bash(pip install *)", "Bash(pip3 install *)",
		"Bash(npm install *)", "Bash(npm i *)", "Bash(npm ci*)",
		"Bash(yarn add *)", "Bash(pnpm add *)",
		"Bash(gem install *)", "Bash(cargo install *)",
		"Bash(go install *)", "Bash(go get *)",
	}
	// Appended here rather than at each plane's assembly point so both planes
	// inherit them from one source: OpencodeConfig rewrites exactly these two
	// functions, so a glob added downstream would be a silent one-plane floor.
	return append(base, ghAskGlobs()...)
}

func secretDenyGlobs(pol *policy.Policy) []string {
	var reads, edits []string
	for _, g := range pol.Slots.SecretDirs {
		reads = append(reads, "Read("+g+")")
		edits = append(edits, "Edit("+g+")")
	}
	for _, g := range pol.Slots.SecretGlobs {
		if collidesWithAllow(g, pol.Slots.SecretAllow) {
			continue
		}
		reads = append(reads, "Read("+g+")")
		edits = append(edits, "Edit("+g+")")
	}
	return append(reads, edits...)
}

func secretAskGlobs(pol *policy.Policy) []string {
	var reads, edits []string
	for _, g := range pol.Slots.SecretAskGlobs {
		if collidesWithAllow(g, pol.Slots.SecretAllow) {
			continue
		}
		reads = append(reads, "Read("+g+")")
		edits = append(edits, "Edit("+g+")")
	}
	return append(reads, edits...)
}

func collidesWithAllow(glob string, allow []string) bool {
	for _, a := range allow {
		if ok, _ := doublestar.Match(glob, a); ok {
			return true
		}
	}
	return false
}

// Duplicated from internal/engine's selfConfigGlobs / gitProtectedGlobs / ciInfraLockGlobs —
// genconfig cannot import internal/engine (would create an import cycle risk and couples
// the declarative-floor package to the Engine's internals). Keep these three lists in sync
// by hand; a drift only weakens the floor, the Engine (internal/engine) stays authoritative.
// Note the intentional prefix difference on directory entries: the Engine lists use `**/`
// prefixes (`**/.claude/settings.json`, `**/.github/workflows/**`) because its matcher sees arbitrary
// absolute paths, while these floor lists keep the plan-literal forms (`.claude/settings.json`,
// `.github/workflows/**`) because native permission matchers treat them project-relative.
// Claude additionally needs `//`-anchored forms for operator config outside the worktree.
var operatorConfigGlobsFloor = []string{
	"**/.config/guardrail/**", "**/guardrail/waivers.toml", "**/guardrail/night.toml",
}

var sessionStoreGlobsFloor = []string{
	"**/guardrail/sessions", "**/guardrail/sessions/**",
	`**\guardrail\sessions`, `**\guardrail\sessions\**`,
}

var selfConfigGlobsFloor = append([]string{
	".codex", ".codex/**",
	".claude/settings.json", ".claude/settings.local.json",
	".claude/hooks/**", ".claude/plugins/**", ".claude/agents/**",
	".claude/commands/**", ".claude/skills/**", ".claude/CLAUDE.md",
	"CLAUDE.md", "AGENTS.md", ".mcp.json", ".envrc",
	"**/.bashrc", "**/.zshrc", "**/.profile", "**/.bash_profile",
	"guardrail.toml", "**/guardrail.toml",
	".guardrail/**",
	"opencode.json", "**/opencode.json",
	".agents/hooks.json",
	"**/.gemini/config/hooks.json",
	"**/.local/bin/guardrail", "**/bin/guardrail",
}, append(operatorConfigGlobsFloor, sessionStoreGlobsFloor...)...)

var gitProtectedGlobsFloor = []string{"**/.git/config", "**/.git/hooks/**"}

var ciInfraLockGlobsFloor = []string{
	".github/workflows/**", ".gitlab-ci.yml", ".circleci/**", "Jenkinsfile",
	".buildkite/**", ".pre-commit-config.yaml", "azure-pipelines.yml",
	"Dockerfile", "docker-compose*.yml", "*.tf", "Makefile", "justfile", "Taskfile.yml",
	"setup.py", "conftest.py", "noxfile.py",
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
	"poetry.lock", "uv.lock", "go.sum", "Gemfile.lock", "mix.lock", "composer.lock",
}

func selfConfigDenyGlobs() []string {
	out := make([]string, 0, len(selfConfigGlobsFloor)+len(gitProtectedGlobsFloor))
	for _, g := range selfConfigGlobsFloor {
		out = append(out, "Edit("+g+")")
	}
	for _, g := range gitProtectedGlobsFloor {
		out = append(out, "Edit("+g+")")
	}
	return out
}

func claudeSelfConfigDenyGlobs() []string {
	out := selfConfigDenyGlobs()
	for _, g := range append(operatorConfigGlobsFloor, sessionStoreGlobsFloor...) {
		out = append(out, "Edit(//"+g+")")
	}
	return out
}

func ciInfraLockAskGlobs() []string {
	out := make([]string, 0, len(ciInfraLockGlobsFloor))
	for _, g := range ciInfraLockGlobsFloor {
		out = append(out, "Edit("+g+")")
	}
	return out
}

func ClaudeConfig(pol *policy.Policy, binary string) Fragment {
	deny := append(bashDenyGlobs(), secretDenyGlobs(pol)...)
	deny = append(deny, claudeSelfConfigDenyGlobs()...)
	ask := append(bashAskGlobs(), secretAskGlobs(pol)...)
	ask = append(ask, ciInfraLockAskGlobs()...)
	return Fragment{
		"hooks": claudeHooks(binary),
		"permissions": map[string]any{
			"allow": claudeFloorAllow(),
			"deny":  deny,
			"ask":   ask,
		},
	}
}

// claudeFloorAllow is the only allow entry the floor carries. Claude Code's
// auto-mode classifier otherwise rejects `guardrail fetch <url>` as
// self-modification, stranding the one sanctioned way to reach the web after
// a native WebFetch deny. The Engine still gates every fetch by the egress
// allowlist, and the pre hook still runs: the entry only skips the classifier.
func claudeFloorAllow() []string {
	return []string{"Bash(guardrail fetch:*)"}
}

func claudeHooks(binary string) map[string]any {
	cmd := HookCommand(binary, "hook", "claude")
	return map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"id":      "guardrail-claude-pre",
				"matcher": planecontract.ClaudePreHookMatcher(),
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd, "timeout": 10},
				},
			},
		},
		"PostToolUse": []any{
			map[string]any{
				"id":      "guardrail-claude-post",
				"matcher": planecontract.ClaudePostHookMatcher(),
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd},
				},
			},
		},
		"SessionStart": []any{
			map[string]any{
				"id":      "guardrail-claude-session-start",
				"matcher": "startup|clear|compact",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd},
				},
			},
		},
		"Stop": []any{
			map[string]any{
				"id": "guardrail-claude-stop",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd, "timeout": 600},
				},
			},
		},
		"SubagentStop": []any{
			map[string]any{
				"id": "guardrail-claude-subagent-stop",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd, "timeout": 600},
				},
			},
		},
	}
}
