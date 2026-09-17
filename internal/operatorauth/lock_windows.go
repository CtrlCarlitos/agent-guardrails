//go:build windows

package operatorauth

import "errors"

// Windows operator approvals remain fail-closed until their native broker
// transport and locking behavior are implemented and validated.
func acquireEnrollmentLock(string) (func(), error) {
	return nil, errors.New("operator enrollment locking is unavailable on Windows")
}
