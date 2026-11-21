package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultTailPollInterval = 100 * time.Millisecond

// TailFilter restricts streamed audit records by plane and/or verdict.
// Empty fields match all values; matching is case-insensitive.
type TailFilter struct {
	Plane   string
	Verdict string
}

// Match reports whether rec satisfies the filter.
func (f TailFilter) Match(rec Record) bool {
	if f.Plane != "" && !strings.EqualFold(rec.Plane, f.Plane) {
		return false
	}
	if f.Verdict != "" && !strings.EqualFold(rec.Decision, f.Verdict) {
		return false
	}
	return true
}

// TailOptions configures live streaming of audit.jsonl across rotations.
type TailOptions struct {
	Path         string
	PollInterval time.Duration
	InitialLines int
	Filter       TailFilter
	OnReady      func()
	Emit         func(Record) error
}

// Tail streams audit records appended to opts.Path until ctx is cancelled or
// opts.Emit returns an error. It follows 20MB segment rotations without holding
// an open file handle between polls, so rotation renames succeed on Windows as
// well as POSIX hosts.
func Tail(ctx context.Context, opts TailOptions) error {
	if opts.Emit == nil {
		return errors.New("audit tail requires Emit callback")
	}
	path := DefaultPath(opts.Path)
	interval := opts.PollInterval
	if interval <= 0 {
		interval = defaultTailPollInterval
	}

	var (
		prevInfo os.FileInfo
		offset   int64
		partial  []byte
	)

	if opts.InitialLines > 0 {
		if segments, err := Segments(path); err == nil && len(segments) > 0 {
			records, _, err := ReadRecords(segments)
			if err != nil {
				return err
			}
			var matched []Record
			for _, rec := range records {
				if opts.Filter.Match(rec) {
					matched = append(matched, rec)
				}
			}
			if len(matched) > opts.InitialLines {
				matched = matched[len(matched)-opts.InitialLines:]
			}
			for _, rec := range matched {
				if err := opts.Emit(rec); err != nil {
					return err
				}
				if ctx.Err() != nil {
					return nil
				}
			}
		}
	}

	if info, err := os.Stat(path); err == nil {
		prevInfo = pinFileID(info)
		offset = info.Size()
	}

	if opts.OnReady != nil {
		opts.OnReady()
	}

	if ctx.Err() != nil {
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					// If the active file was just rotated and the new file has
					// not been created yet, drain any trailing records from the
					// rotated segment that matches prevInfo.
					if prevInfo != nil {
						if rotated, ok := findRotatedSegment(path, prevInfo); ok {
							if err := drainFrom(rotated, offset, &partial, opts.Filter, opts.Emit); err != nil {
								return err
							}
						}
						prevInfo = nil
						offset = 0
						partial = nil
					}
					continue
				}
				return err
			}
			info = pinFileID(info)

			switch {
			case prevInfo == nil:
				// File appeared after startup: read from offset 0.
				prevInfo = info
				offset = 0
			case !os.SameFile(prevInfo, info):
				// Segment rotated: drain the old rotated file from our last
				// offset first so zero records written right before rename are lost.
				if rotated, ok := findRotatedSegment(path, prevInfo); ok {
					if err := drainFrom(rotated, offset, &partial, opts.Filter, opts.Emit); err != nil {
						return err
					}
				}
				prevInfo = info
				offset = 0
				partial = nil
			case info.Size() < offset:
				// File was truncated in place.
				prevInfo = info
				offset = 0
				partial = nil
			}

			if info.Size() > offset {
				nextOffset, err := readAppended(path, offset, &partial, opts.Filter, opts.Emit)
				if err != nil {
					return err
				}
				offset = nextOffset
				prevInfo = info
			}
		}
	}
}

// pinFileID forces Go on Windows to load the NTFS volume/index file ID while
// the path still refers to this file. Go's os.Stat on Windows defers
// GetFileInformationByHandle until the first os.SameFile call; calling it only
// after a rename reopens the new file at the same path and falsely reports
// SameFile == true.
func pinFileID(info os.FileInfo) os.FileInfo {
	if info != nil {
		_ = os.SameFile(info, info)
	}
	return info
}

func findRotatedSegment(path string, prevInfo os.FileInfo) (string, bool) {
	base := strings.TrimSuffix(path, ".jsonl")
	rotated, err := filepath.Glob(base + "-*.jsonl")
	if err != nil || len(rotated) == 0 {
		return "", false
	}
	sort.Strings(rotated)
	// Walk newest-first so we immediately match the most recent rotation.
	for i := len(rotated) - 1; i >= 0; i-- {
		segInfo, err := os.Stat(rotated[i])
		if err == nil && os.SameFile(prevInfo, pinFileID(segInfo)) {
			return rotated[i], true
		}
	}
	return "", false
}

func drainFrom(path string, offset int64, partial *[]byte, filter TailFilter, emit func(Record) error) error {
	_, err := readAppended(path, offset, partial, filter, emit)
	return err
}

func readAppended(path string, offset int64, partial *[]byte, filter TailFilter, emit func(Record) error) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return offset, nil
		}
		return offset, err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return offset, err
	}
	if len(data) == 0 {
		return offset, nil
	}
	nextOffset := offset + int64(len(data))

	buf := append(*partial, data...)
	*partial = nil

	for {
		idx := bytes.IndexByte(buf, '\n')
		if idx < 0 {
			if len(buf) > 0 {
				*partial = append((*partial)[:0], buf...)
			}
			break
		}
		line := bytes.TrimSpace(buf[:idx])
		buf = buf[idx+1:]
		if len(line) == 0 {
			continue
		}
		var rec Record
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		if !filter.Match(rec) {
			continue
		}
		if err := emit(rec); err != nil {
			return nextOffset, err
		}
	}
	return nextOffset, nil
}
