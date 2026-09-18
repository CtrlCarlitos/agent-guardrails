package genconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
)

var utf8ByteOrderMark = []byte{0xEF, 0xBB, 0xBF}

// ReadJSONObject reads a plane settings file as a JSON object. A UTF-8 byte
// order mark is stripped first: Windows editors (Notepad, PowerShell 5) add
// one, encoding/json rejects it, and a settings file the operator once
// opened in Notepad must not read as "not a JSON object". A missing file
// surfaces os.IsNotExist so callers keep their create-on-absent paths.
func ReadJSONObject(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimPrefix(raw, utf8ByteOrderMark)
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("null")
	}
	return doc, nil
}
