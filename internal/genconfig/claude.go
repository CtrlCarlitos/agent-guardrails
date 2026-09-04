// Package genconfig translates a merged policy into each plane's native
// declarative config (the "declarative floor") and merges it into that plane's
// settings file.
package genconfig

import (
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
	return []string{
		"Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(rm -r -f *)", "Bash(rm -f -r *)",
		"Bash(dd *)",
		"Bash(mkfs*)", "Bash(wipefs *)",
		"Bash(shred *)", "Bash(srm *)",
		"Bash(sudo *)", "Bash(su *)", "Bash(su)", "Bash(doas *)",
		"Bash(git push --force*)", "Bash(git push -f*)",
		"Bash(git clean -f*)", "Bash(git clean -xf*)", "Bash(git clean -fx*)",
		"Bash(git clean -df*)", "Bash(git clean -fd*)",
		"Bash(git reset --hard*)", "Bash(git reset --keep*)",
		"Bash(git config *)",
		"Bash(git filter-branch*)", "Bash(git filter-repo*)",
		"Bash(pip install --index-url*)", "Bash(pip3 install --index-url*)",
		"Bash(npm install --registry*)",
		"Bash(docker compose down*)",
		"Bash(docker system prune*)", "Bash(docker volume prune*)", "Bash(docker network prune*)",
	}
}

// bashAskGlobs is the curated coarse floor for P1 ask-tier shell commands.
func bashAskGlobs() []string {
	return []string{
		"Bash(chmod -R *)", "Bash(chmod 777 *)", "Bash(chmod -R 777 *)",
		"Bash(chown -R *)",
		"Bash(truncate *)",
		"Bash(kill -9 *)", "Bash(killall *)", "Bash(pkill *)",
		"Bash(find * -delete)",
		"Bash(git checkout .)", "Bash(git restore .)",
		"Bash(git branch -D *)", "Bash(git commit --amend*)",
		"Bash(git remote add *)", "Bash(git remote set-url *)",
		"Bash(git stash clear)", "Bash(git stash drop*)",
		"Bash(git push * main)", "Bash(git push * master)", "Bash(git push --tags*)",
		"Bash(pip install *)", "Bash(pip3 install *)",
		"Bash(npm install *)", "Bash(npm i *)", "Bash(npm ci*)",
		"Bash(yarn add *)", "Bash(pnpm add *)",
		"Bash(gem install *)", "Bash(cargo install *)",
		"Bash(go install *)", "Bash(go get *)",
	}
}

func secretDenyGlobs(pol *policy.Policy) []string {
	var reads, edits []string
	for _, g := range pol.Slots.SecretGlobs {
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
// prefixes (`**/.claude/**`, `**/.github/workflows/**`) because its matcher sees arbitrary
// absolute paths, while these floor lists keep the plan-literal forms (`.claude/**`,
// `.github/workflows/**`) because Claude's permission matcher treats them project-relative.
var selfConfigGlobsFloor = []string{
	".claude/**", "CLAUDE.md", "AGENTS.md", ".mcp.json", ".envrc",
	"**/.bashrc", "**/.zshrc", "**/.profile", "**/.bash_profile",
}

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

func ciInfraLockAskGlobs() []string {
	out := make([]string, 0, len(ciInfraLockGlobsFloor))
	for _, g := range ciInfraLockGlobsFloor {
		out = append(out, "Edit("+g+")")
	}
	return out
}

func ClaudeConfig(pol *policy.Policy, binary string) Fragment {
	deny := append(bashDenyGlobs(), secretDenyGlobs(pol)...)
	deny = append(deny, selfConfigDenyGlobs()...)
	ask := append(bashAskGlobs(), ciInfraLockAskGlobs()...)
	return Fragment{
		"hooks": claudeHooks(binary),
		"permissions": map[string]any{
			"deny": deny,
			"ask":  ask,
		},
	}
}

func claudeHooks(binary string) map[string]any {
	cmd := binary + " hook claude"
	return map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"id":      "guardrail-claude-pre",
				"matcher": "Bash|Read|Edit|Write|MultiEdit",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd, "timeout": 10},
				},
			},
		},
		"PostToolUse": []any{
			map[string]any{
				"id":      "guardrail-claude-post",
				"matcher": "Write|Edit|MultiEdit",
				"hooks": []any{
					map[string]any{"type": "command", "command": cmd},
				},
			},
		},
	}
}
