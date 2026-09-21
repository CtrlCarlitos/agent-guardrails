//go:build !windows

package approval_test

import (
	"errors"
	"syscall"
)

func connectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
