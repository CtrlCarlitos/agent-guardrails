package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Power control: ending the machine's uptime ends the session, kills
// unsaved work, and cannot be undone by anything the agent does afterwards
// (#140). The verdict is an ask, not a deny — rebooting a machine the
// operator handed the agent is an operator decision, made per call, the same
// tier chmod 777 gets. The ask is classified never-relaxed (ADR-0018 set,
// policy.NeverRelaxable): an overnight window must not answer it on the
// operator's behalf.
//
// One checker covers both shells because the command text arrives through
// the same simple chain either way: `Stop-Computer` and `shutdown /r` are
// just different spellings of the act, and the measured corpus in #140
// treats them as one family.

// powerOffCommands ask on every flag shape: there is no spelling of reboot,
// poweroff or halt that does anything except end the uptime.
var powerOffCommands = map[string]bool{
	"reboot": true, "poweroff": true, "halt": true,
}

// shutdownSafeFlags are the spellings that do not end the uptime: cancel a
// pending shutdown (-c, /a), print the warning wall message without acting
// (-k), or print help (--help, /?). checkShutdownFlags classifies with mode
// semantics rather than this table alone; the table documents the set.
var shutdownSafeFlags = map[string]bool{
	"-c": true, "-k": true, "--help": true,
	"/a": true, "/?": true,
}

// powerOffVerbs are the systemctl subcommands that end the uptime. The verb
// is the first non-flag operand; `systemctl status reboot` is a read and
// stays allowed because "reboot" is not its first operand.
var powerOffVerbs = map[string]bool{
	"reboot": true, "poweroff": true, "halt": true,
}

func checkPowerControl(s Simple) *policy.Verdict {
	command := head(s.Argv)
	switch {
	case powerOffCommands[command]:
		return ask("P1.power", command+" ends the machine's uptime; unsaved work is lost and the session cannot continue")
	case command == "shutdown":
		return checkShutdownFlags(s.Argv[1:])
	case command == "systemctl":
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if powerOffVerbs[a] {
				return ask("P1.power", "systemctl "+a+" ends the machine's uptime; unsaved work is lost and the session cannot continue")
			}
			return nil // first operand is the subcommand; anything else is a different act
		}
		return nil
	case command == "init" || command == "telinit":
		// Runlevel 0 halts the machine, 6 reboots it. Other runlevels
		// switch service sets and stay recoverable.
		for _, a := range s.Argv[1:] {
			if a == "0" || a == "6" {
				return ask("P1.power", command+" "+a+" ends the machine's uptime; unsaved work is lost and the session cannot continue")
			}
			return nil // first operand is the runlevel
		}
		return nil
	case command == "stop-computer" || command == "restart-computer":
		// -WhatIf is PowerShell's dry run; it removes nothing and reboots
		// nothing (same posture checkPSRemoveItem takes).
		for _, a := range s.Argv[1:] {
			if strings.EqualFold(a, "-whatif") {
				return nil
			}
		}
		return ask("P1.power", command+" ends the machine's uptime; unsaved work is lost and the session cannot continue")
	}
	return nil
}

// checkShutdownFlags classifies a shutdown invocation by its flags.
//
// Three spellings act on nothing and stay allowed: --help (and /?) print
// text, /a aborts a pending shutdown, -c cancels one, and -k prints the
// warning wall message without powering anything off — in cancel and warn
// modes the time operand that would otherwise schedule the shutdown is
// ignored by shutdown itself, so `shutdown -c now` and `shutdown -k now`
// stay allowed. A dangerous flag mixed into a cancel/warn invocation asks:
// the modes are mutually exclusive in real usage and the mixture is not a
// shape worth second-guessing.
//
// Everything else asks: bare `shutdown` schedules +1 on POSIX, a time
// operand (`now`, `+5`, `20:30`) schedules it, and an unrecognized flag may
// be a spelling of the act this rule exists for — the safe direction on an
// unrecognized spelling of a power command is the operator.
func checkShutdownFlags(args []string) *policy.Verdict {
	reason := "shutdown ends the machine's uptime; unsaved work is lost and the session cannot continue"
	for _, a := range args {
		switch strings.ToLower(a) {
		case "--help", "/?", "/a":
			return nil // short-circuit modes: they act on nothing
		}
	}
	cancelOrWarn := false
	for _, a := range args {
		switch strings.ToLower(a) {
		case "-c", "-k":
			cancelOrWarn = true
		}
	}
	for _, a := range args {
		flag := strings.ToLower(a)
		if flag == "-c" || flag == "-k" {
			continue
		}
		if strings.HasPrefix(flag, "-") || strings.HasPrefix(flag, "/") {
			// An unrecognized flag in a cancel/warn invocation: the mixture
			// is not a shape shutdown honours, and one of the two is lying.
			return ask("P1.power", reason)
		}
		// A time operand. In cancel/warn mode shutdown ignores it; in any
		// other mode it schedules the shutdown.
		if cancelOrWarn {
			continue
		}
		return ask("P1.power", reason)
	}
	if !cancelOrWarn {
		// No args at all: POSIX schedules +1.
		return ask("P1.power", reason)
	}
	return nil
}
