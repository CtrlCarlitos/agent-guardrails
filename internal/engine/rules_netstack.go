package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Network-stack control (#286): no rule touched adapter, wifi or resolver
// configuration in any shell. The DNS class is the worst of the family — a
// poisoned resolver launders blocked hosts through the egress allowlist
// while everything appears to work — and adapter/wifi control ends other
// work on the machine. The verdict is an ask, never night-relaxed (the
// P1.power ruling property: machine-level state an overnight window must
// not answer on the operator's behalf), waivable per ADR-0003 like every
// ordinary ask.
//
// One checker covers both shells, as checkPowerControl does: `netsh`, `ip`
// and PowerShell cmdlets arrive through the same simple chain. Read twins
// (show/status/list shapes, Get- verbs, ipconfig /all and /flushdns) and
// dry-run shapes (-WhatIf) stay allowed: this is a mutation rule, not a
// tool deny.

// netStackAskingHeads ask regardless of operands: there is no spelling of
// these that does anything but control the stack.
var netStackAskingHeads = map[string]bool{
	"netsh":  false, // handled with subcommand shape below
	"rfkill": false, // block/unblock are the asking shapes
}

// netStackAsks maps a simple's head (and, where the verb decides, its first
// operands) to the reason fragment naming the act. PowerShell cmdlet heads
// match case-insensitively; everything else exactly.
var netStackHeads = map[string]string{
	"disable-netadapter":         "disables a network adapter",
	"enable-netadapter":          "re-enables a network adapter",
	"restart-netadapter":         "restarts a network adapter",
	"set-dnsclientserveraddress": "sets the resolver a network interface uses",
	"set-netipaddress":           "changes a network interface address",
	"set-netipinterface":         "changes a network interface configuration",
}

func checkNetStackControl(s Simple) *policy.Verdict {
	// Dry-run shapes preview the change and change nothing (#286 corpus).
	for _, a := range s.Argv[1:] {
		if strings.EqualFold(a, "-WhatIf") {
			return nil
		}
	}
	command := strings.ToLower(head(s.Argv))
	if reason, ok := netStackHeads[command]; ok {
		return ask("P1.net-stack", head(s.Argv)+" "+reason+"; every later name resolution and connection on this machine is affected")
	}
	args := s.Argv[1:]
	lower := make([]string, len(args))
	for i, a := range args {
		lower[i] = strings.ToLower(a)
	}
	switch command {
	case "netsh":
		return checkNetshNetStack(lower)
	case "nmcli":
		return checkNmcliNetStack(lower)
	case "rfkill":
		if len(lower) > 0 && (lower[0] == "block" || lower[0] == "unblock") {
			return ask("P1.net-stack", "rfkill "+lower[0]+" toggles a wireless device's radio; connectivity for the machine is affected")
		}
	case "ip":
		// ip link set dev X down|up — the family's only mutating spelling
		// that stays a read in every other shape (show/addr/route).
		if len(lower) >= 2 && lower[0] == "link" && lower[1] == "set" {
			for _, a := range lower[2:] {
				if a == "down" || a == "up" {
					return ask("P1.net-stack", "ip link set ... "+a+" changes a network interface's admin state")
				}
			}
		}
	case "ifconfig":
		for _, a := range lower {
			if a == "down" || a == "up" {
				return ask("P1.net-stack", "ifconfig ... "+a+" changes a network interface's admin state")
			}
		}
	case "networksetup":
		if len(lower) > 0 && strings.HasPrefix(lower[0], "-setairportpower") {
			return ask("P1.net-stack", "networksetup -setairportpower toggles the Wi-Fi radio")
		}
	case "ipconfig":
		for _, a := range lower {
			if a == "/release" || a == "/renew" {
				return ask("P1.net-stack", "ipconfig "+a+" drops or re-acquires the machine's DHCP lease; resolver configuration changes with it")
			}
		}
	}
	return nil
}

// checkNetshNetStack covers the netsh families from the corpus: interface
// enable/disable, wlan disconnect/delete, and interface ip set (dns,
// address, dhcp). Every other netsh shape — show, and the read verbs —
// stays allowed.
func checkNetshNetStack(lower []string) *policy.Verdict {
	if len(lower) < 2 {
		return nil
	}
	switch {
	case lower[0] == "interface" && lower[1] == "set":
		for _, a := range lower[2:] {
			if a == "disable" || a == "enable" {
				return ask("P1.net-stack", "netsh interface set ... "+a+" changes a network adapter's admin state")
			}
		}
	case lower[0] == "interface" && (lower[1] == "ip" || lower[1] == "ipv4" || lower[1] == "ipv6") && len(lower) > 2 && lower[2] == "set":
		return ask("P1.net-stack", "netsh "+lower[1]+" set changes interface address or resolver configuration")
	case lower[0] == "wlan" && lower[1] == "disconnect":
		return ask("P1.net-stack", "netsh wlan disconnect drops the machine's Wi-Fi association")
	case lower[0] == "wlan" && lower[1] == "delete":
		return ask("P1.net-stack", "netsh wlan delete removes a stored Wi-Fi profile")
	}
	return nil
}

// checkNmcliNetStack covers nmcli's mutating shapes: radio off/on,
// networking off/on, connection down/up. Status and list shapes stay reads.
func checkNmcliNetStack(lower []string) *policy.Verdict {
	if len(lower) < 2 {
		return nil
	}
	verb, object := lower[0], lower[1]
	switch {
	case verb == "radio" && (object == "off" || object == "on" || len(lower) > 2 && (lower[2] == "off" || lower[2] == "on")):
		return ask("P1.net-stack", "nmcli radio toggles a wireless radio")
	case verb == "networking" && (object == "off" || object == "on"):
		return ask("P1.net-stack", "nmcli networking toggles the whole networking stack")
	case verb == "connection" && (object == "down" || object == "up"):
		return ask("P1.net-stack", "nmcli connection "+object+" changes a network connection's state")
	}
	return nil
}
