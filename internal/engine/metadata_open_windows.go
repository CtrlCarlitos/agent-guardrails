//go:build windows

package engine

import "os"

func openMetadataFile(path string) (*os.File, error) {
	return os.Open(path)
}
