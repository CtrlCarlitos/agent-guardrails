package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// fileInUseByAnotherProcess reports Windows' refusal to open a file another
// process holds without sharing: what a reader meets while a sibling
// transaction is replacing or removing it.
func fileInUseByAnotherProcess(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
