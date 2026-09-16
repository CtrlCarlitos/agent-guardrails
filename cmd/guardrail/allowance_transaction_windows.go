//go:build windows

package main

import (
	"fmt"
	"os"
)

func validateAllowanceOwner(os.FileInfo) error {
	return fmt.Errorf("persistent allowances are unavailable on Windows")
}
