package main

import (
	"os/exec"
	"regexp"
	"strconv"
)

// opencodeMajorProbe is the seam tests override to fake `opencode --version`.
var opencodeMajorProbe = func() (string, error) {
	binary, err := exec.LookPath("opencode")
	if err != nil {
		return "", err
	}
	out, err := exec.Command(binary, "--version").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// opencodeMajorCache holds the resolved major so one process run probes the
// plane binary at most once; 0 means unknown, resolved records whether the
// probe already ran (a failed probe must not re-run per call either).
var (
	opencodeMajorCache    int
	opencodeMajorResolved bool
)

// opencodeMajor reports the installed opencode binary's major version: 1 for
// OpenCode 1.x, 2 for OpenCode 2.x, 0 when no binary can be probed or the
// version cannot be parsed. Callers treat 0 as "assume V1, say so loudly".
func opencodeMajor() int {
	if !opencodeMajorResolved {
		output, err := opencodeMajorProbe()
		if err != nil {
			opencodeMajorCache = 0
		} else {
			opencodeMajorCache = parseOpencodeMajor(output)
		}
		opencodeMajorResolved = true
	}
	return opencodeMajorCache
}

// opencodeVersionToken matches the first version-looking token in the output.
// V1 prints a bare version ("1.19.5"); V2 prefixes the app name
// ("opencode v2.3.0"), and pre-release builds append a suffix.
var opencodeVersionToken = regexp.MustCompile(`v?([0-9]+)\.[0-9]+`)

// parseOpencodeMajor extracts the major from an `opencode --version` output
// string. Only majors 1 and 2 are known; anything else is 0.
func parseOpencodeMajor(output string) int {
	match := opencodeVersionToken.FindStringSubmatch(output)
	if match == nil {
		return 0
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	if major != 1 && major != 2 {
		return 0
	}
	return major
}
