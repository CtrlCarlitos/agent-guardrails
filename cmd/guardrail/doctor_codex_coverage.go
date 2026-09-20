package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/coverage"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

func cmdDoctorCodexCoverage(args []string, stdout, stderr io.Writer) int {
	var plane, schema string
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if (flag != "--coverage" && flag != "--schema") || i+1 == len(args) {
			fmt.Fprintln(stderr, "guardrail: usage: doctor --coverage codex --schema <Responses-tools.json>")
			return 2
		}
		i++
		switch flag {
		case "--coverage":
			if plane != "" {
				fmt.Fprintln(stderr, "guardrail: duplicate --coverage")
				return 2
			}
			plane = args[i]
		case "--schema":
			if schema != "" {
				fmt.Fprintln(stderr, "guardrail: duplicate --schema")
				return 2
			}
			schema = args[i]
		}
	}
	if plane != "codex" || schema == "" {
		fmt.Fprintln(stderr, "guardrail: use doctor --coverage codex --schema <Responses-tools.json>; supply a captured runtime tools array (inventory only, no model call)")
		return 2
	}
	f, err := os.Open(schema)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: codex coverage: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	defer f.Close()
	inv, err := coverage.ScanCodexSchema(f)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: codex coverage incomplete: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	fmt.Fprintf(stdout, "codex coverage: captured schema %s\nsha256: %s\n", safetext.SingleLine(schema), inv.SHA256)
	fmt.Fprintln(stdout, "scope: supplied configuration only; not a complete runtime inventory or evidence that hooks fire")
	if runtime.GOOS == "windows" {
		fmt.Fprintln(stdout, "runtime status: registered, unenforced on Windows; command_execution PreToolUse dispatch is blocked by openai/codex#24453; schema rows are contract inventory, not runtime coverage")
	}
	fmt.Fprintln(stdout, "tool\thook identity\tcapability\tclassification")
	exit := 0
	for _, row := range inv.Tools {
		hook, capability := row.Hook, string(row.Capability)
		if hook == "" {
			hook = "-"
		}
		if capability == "" {
			capability = "-"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", row.Name, hook, capability, row.Status)
		if row.Status == "uncontracted" || row.Status == "unsupported-schema" || row.Status == "hosted-no-local-hook" {
			exit = 1
		}
	}
	fmt.Fprintln(stdout, "unknown native tools fail closed when delivered to Guardrail; hosted declarations do not pass through local hooks")
	fmt.Fprintln(stdout, "web.run classification depends on call arguments; write_stdin remains denied (ADR-0014)")
	fmt.Fprintln(stdout, "code-mode schemas do not enumerate inner tools; delegation remains denied")
	if len(inv.Unobserved) > 0 {
		fmt.Fprintf(stdout, "unobserved contract entries (not proven retired): %s\n", strings.Join(inv.Unobserved, ", "))
	}
	if runtime.GOOS == "windows" {
		exit = 1
	}
	return exit
}
