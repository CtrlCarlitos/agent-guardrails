package approval

import (
	"os"
	"runtime"
)

// InstanceLabel names the guardrail instance an approval page belongs to. On a
// machine with a Windows instance and a WSL instance, both use the rpId
// localhost and each has its own credential store, so an operator has to be able
// to tell which one is asking before authenticating (#383).
func InstanceLabel() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "an unknown host"
	}
	if distro := os.Getenv("WSL_DISTRO_NAME"); distro != "" {
		return "WSL " + distro + " on " + host
	}
	return runtime.GOOS + " on " + host
}
