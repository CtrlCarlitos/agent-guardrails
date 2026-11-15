package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #286: no engine rule touched network-stack control. The DNS class is the
// worst of the family: a poisoned resolver launders blocked hosts through
// the egress allowlist while everything appears to work. P1.net-stack asks
// in every shell, is never night-relaxed (the P1.power ruling property), and
// stays waivable per ADR-0003.
func TestNetStackControlAsks(t *testing.T) {
	for _, command := range []string{
		// adapter up/down
		`netsh interface set interface "Wi-Fi" disable`,
		`netsh interface set interface "Wi-Fi" enable`,
		`Disable-NetAdapter -Name Wi-Fi`,
		`Enable-NetAdapter -Name Wi-Fi`,
		`Restart-NetAdapter -Name Wi-Fi`,
		`ip link set dev wlan0 down`,
		`ip link set dev wlan0 up`,
		`ifconfig wlan0 down`,
		`networksetup -setairportpower en0 off`,
		// wifi control
		`netsh wlan disconnect`,
		`netsh wlan delete profile name=*`,
		`nmcli radio wifi off`,
		`nmcli networking off`,
		`nmcli connection down id Home`,
		`rfkill block wifi`,
		// address / DNS / DHCP mutation — the quiet class
		`Set-DnsClientServerAddress -InterfaceAlias Wi-Fi -ServerAddresses 1.2.3.4`,
		`Set-NetIPAddress -IPAddress 1.2.3.4`,
		`Set-NetIPInterface -Dhcp Enabled`,
		`netsh interface ip set dns "Wi-Fi" static 1.2.3.4`,
		`netsh interface ip set address "Wi-Fi" static 1.2.3.4 255.255.255.0`,
		`netsh interface ip set dns "Wi-Fi" dhcp`,
		`ipconfig /release`,
		`ipconfig /renew`,
	} {
		if v := evalBash(t, command); v == nil || v.Decision != policy.Ask || v.RuleID != "P1.net-stack" {
			t.Errorf("%q -> %+v, want ask/P1.net-stack", command, v)
		}
	}
}

// Read twins and dry-run shapes stay allowed.
func TestNetStackReadTwinsAllow(t *testing.T) {
	for _, command := range []string{
		`ipconfig /all`,
		`ipconfig /flushdns`,
		`Get-NetAdapter`,
		`nmcli dev wifi list`,
		`nmcli radio wifi`,
		`ip link show`,
		`netsh wlan show profiles`,
		`arp -a`,
		`Set-DnsClientServerAddress -InterfaceAlias Wi-Fi -ServerAddresses 1.2.3.4 -WhatIf`,
	} {
		if v := evalBash(t, command); v != nil {
			t.Errorf("%q -> %+v, want allow", command, v)
		}
	}
}

// The ask is never relaxed by night mode: the P1.power ruling property.
func TestNetStackAskIsNeverRelaxable(t *testing.T) {
	if !policy.NeverRelaxable("P1.net-stack") {
		t.Fatal("P1.net-stack must join policy.NeverRelaxable")
	}
	// The pinned contract (grants_drift_test): the never-relaxed set is
	// never grantable either — P1.power identical. The ADR-0003 overlay
	// waiver is the separate, per-project mechanism that still applies.
	if !policy.NeverGrantable("P1.net-stack") {
		t.Fatal("P1.net-stack must mirror P1.power: never grantable")
	}
}

func TestNetStackUnrelatedSpellingsUnaffected(t *testing.T) {
	for _, command := range []string{
		`nmcli connection show`,
		`netsh wlan show drivers`,
	} {
		if v := evalBash(t, command); v != nil && strings.Contains(v.RuleID, "net-stack") {
			t.Errorf("%q -> %+v, must not fire net-stack", command, v)
		}
	}
}
