//go:build windows

package approval_test

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

func connectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}

func TestWindowsConnectionRefusedClassification(t *testing.T) {
	if err := fmt.Errorf("connectex: %w", windows.WSAECONNREFUSED); !connectionRefused(err) {
		t.Fatalf("wrapped WSAECONNREFUSED was not classified: %v", err)
	}
	if connectionRefused(windows.WSAETIMEDOUT) {
		t.Fatal("WSAETIMEDOUT was classified as a refused connection")
	}
}
