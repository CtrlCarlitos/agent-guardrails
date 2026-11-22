package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func wantSecretDeny(t *testing.T, cmd string) {
	t.Helper()
	v := evalEnv(t, cmd)
	if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
		t.Errorf("%q: got %s %s (%s), want deny P4.secret-path", cmd, v.Decision, v.RuleID, v.Reason)
	}
}

// A file cmdlet's operand is a path whether or not it has a separator in it.
// The generic operand reader only treats a bare word as a path for commands it
// knows read files, and it knew `cat` but not `Get-Content`: `cat .env` was
// denied while `Get-Content .env` read the secret, though `Get-Content .\.env`
// was denied too. The spelling of the path decided the verdict.
func TestWindowsPowerShellBareSecretOperandIsDenied(t *testing.T) {
	for _, cmd := range []string{
		`Get-Content .env`,
		`gc .env`,
		`type .env`,
		`Get-Content -Path .env`,
		`Get-Content -LiteralPath .env`,
		`Get-Content -Path:.env`,
		`Get-Content -Raw .env`,
		`Get-Content -TotalCount 5 .env`,
		`Get-Content -Encoding utf8 .env`,
		`Get-Content .env -Tail 3`,
		`Get-Content .env | Select-String FAKE`,
		`Select-String FAKE .env`,
		`sls FAKE .env`,
		`Select-String -Pattern FAKE .env`,
		`Select-String -Path .env -Pattern FAKE`,
		`Select-String .env -Pattern FAKE`,
		`Select-String -SimpleMatch FAKE .env`,
		`Copy-Item .env copy.txt`,
		`cpi .env copy.txt`,
		`copy .env copy.txt`,
		`Copy-Item -Path .env -Destination copy.txt`,
		`Move-Item .env moved.txt`,
		`move .env moved.txt`,
		`Rename-Item .env renamed.txt`,
		`ren .env renamed.txt`,
		`Format-Hex .env`,
		`Import-Csv .env`,
		// Quoting does not change what the word names.
		`Get-Content ".env"`,
		`Get-Content '.env'`,
	} {
		wantSecretDeny(t, cmd)
	}
}

// The path can be named in every position PowerShell binds one from. Each of
// these was allowed by a reader that tried to exempt some word as "not a
// path": a parameter the reader did not know, a value it took for a
// non-path parameter's, or the text Select-String searches for.
func TestWindowsPowerShellSecretOperandIsDeniedInEveryPosition(t *testing.T) {
	for _, cmd := range []string{
		// A path parameter takes an array, with or without a space.
		`Get-Content notes.txt,.env`,
		`Get-Content .env,notes.txt`,
		`Get-Content -Path notes.txt,.env`,
		`Get-Content notes.txt, .env`,
		`Select-String FAKE notes.txt,.env`,
		`Select-String -Path notes.txt, .env FAKE`,
		`Select-String -Path notes.txt, .\.env FAKE`,
		`Copy-Item notes.txt,.env backup`,
		// Aliases of -LiteralPath.
		`Select-String -PSPath .env FAKE`,
		`Select-String -PSPath .\.env FAKE`,
		`sls -LP .env FAKE`,
		`Get-Content -PSPath .env`,
		// `-Name: value` binds the next word.
		`Select-String -Path: .env FAKE`,
		`Select-String -Path: .\.env FAKE`,
		`Get-Content -Path: .env`,
		`type -Path:.env`,
		`type -LiteralPath:.env`,
		// PowerShell accepts an en dash, em dash or horizontal bar as a dash.
		"Select-String .env –Pattern FAKE",
		"Select-String .\\.env —Pattern FAKE",
		"Get-Content –Path .env",
		// A quoted word is an argument to PowerShell however it is spelled, and
		// the quotes are gone by the time the Engine reads it: `'-*'` is the
		// pattern here, and `.env` the file it is matched against.
		`Select-String '-*' .env`,
		`Select-String '-*' .\.env`,
		`Select-String -NotMatch '-Encoding' .env`,
		`Select-String -NotMatch '-Encoding' .\.env`,
		`Select-String -NotMatch '-Pattern' .env`,
		`Select-String -NotMatch --Pattern .env`,
		`Select-String -NotMatch -- -Pattern .\.env`,
	} {
		wantSecretDeny(t, cmd)
	}
}

// The cost of reading every word as a path: a word that is not a path but is
// spelled like a secret is denied. Pinned so the trade is visible, and so a
// future exemption has to say which of the spellings above it reopens.
func TestWindowsPowerShellSecretLookingNonPathWordsAreDenied(t *testing.T) {
	for _, cmd := range []string{
		`Select-String .env notes.txt`,
		`Select-String -Pattern .env -Path notes.txt`,
		`Get-Content notes.txt -Delimiter .env`,
		// Consistent with `cp .env.example .env`, which is denied too.
		`Copy-Item .env.example .env`,
	} {
		wantSecretDeny(t, cmd)
	}
}

func TestWindowsPowerShellOrdinaryFileCmdletsStayAllowed(t *testing.T) {
	for _, cmd := range []string{
		`Get-Content notes.txt`,
		`gc notes.txt`,
		`type notes.txt`,
		`Get-Content -Path notes.txt -TotalCount 5`,
		`Get-Content -Encoding utf8 notes.txt`,
		`Get-Content notes.txt,other.txt`,
		`Get-Content notes.txt -ErrorAction Stop`,
		`Select-String TODO notes.txt`,
		`sls TODO notes.txt -Context 2`,
		`Select-String -Pattern TODO -Path notes.txt`,
		`Select-String -SimpleMatch -CaseSensitive TODO notes.txt`,
		`Select-String 'a|b' notes.txt`,
		`Copy-Item notes.txt copy.txt`,
		`Copy-Item -Path notes.txt -Destination copy.txt -Force`,
		`Move-Item notes.txt moved.txt`,
		`Rename-Item notes.txt renamed.txt`,
		`Format-Hex notes.txt`,
		`Import-Csv data.csv -Delimiter ';'`,
	} {
		if v := evalEnv(t, cmd); v.Decision != policy.Allow {
			t.Errorf("%q: got %s %s (%s), want allow", cmd, v.Decision, v.RuleID, v.Reason)
		}
	}
}

// POSIX `type` names a command. Reading that name as a path changes nothing
// unless the name is a secret's.
func TestWindowsPowerShellTypeStillNamesCommandsOnPOSIX(t *testing.T) {
	for _, cmd := range []string{`type git`, `type -a python`, `type -t ls`} {
		if v := evalEnv(t, cmd); v.Decision != policy.Allow {
			t.Errorf("%q: got %s %s (%s), want allow", cmd, v.Decision, v.RuleID, v.Reason)
		}
	}
}

// The same commands reach the Engine from a Bash tool on a Windows host, where
// the shell underneath may still be PowerShell.
func TestWindowsPowerShellBareSecretOperandIsDeniedFromTheBashTool(t *testing.T) {
	root := repoRootForHost()
	for _, cmd := range []string{`Get-Content .env`, `Select-String FAKE .env`, `Copy-Item .env copy.txt`, `type .env`} {
		v := Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
			Capability: policy.CapabilityCommand, Command: cmd, CWD: root, RepoRoot: root}, envPol())
		if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
			t.Errorf("%q: got %s %s (%s), want deny P4.secret-path", cmd, v.Decision, v.RuleID, v.Reason)
		}
	}
}
