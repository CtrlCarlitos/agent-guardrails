//go:build windows

package main

import "github.com/CtrlCarlitos/agent-guardrails/internal/privatefs"

func securePrivateDir(dir string) error {
	return privatefs.SecureDir(dir)
}
