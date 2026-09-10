package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/night"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const defaultNightDuration = 8 * time.Hour

func cmdNight(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: night requires on, off, or status")
		return 2
	}
	path, err := night.DefaultPath()
	if err != nil {
		return nightError(err, stderr)
	}

	switch args[0] {
	case "on":
		return cmdNightOn(path, args[1:], stdout, stderr)
	case "off":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "guardrail: night off takes no arguments")
			return 2
		}
		if err := night.Remove(path); err != nil {
			return nightError(err, stderr)
		}
		fmt.Fprintln(stdout, "night mode off")
		return 0
	case "status":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "guardrail: night status takes no arguments")
			return 2
		}
		state, err := night.Load(path, time.Now())
		if err != nil {
			return nightError(err, stderr)
		}
		if !state.Active {
			fmt.Fprintln(stdout, "night mode inactive")
			return 1
		}
		fmt.Fprintln(stdout, state.Banner())
		return 0
	default:
		fmt.Fprintf(stderr, "guardrail: unknown night action %q\n", args[0])
		return 2
	}
}

func cmdNightOn(path string, args []string, stdout, stderr io.Writer) int {
	if repeatedNightFlag(args, "for") || repeatedNightFlag(args, "until") {
		fmt.Fprintln(stderr, "guardrail: night on accepts each expiry flag at most once")
		return 2
	}
	fs := flag.NewFlagSet("night on", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	var durationText, untilText string
	fs.StringVar(&durationText, "for", "", "night mode duration")
	fs.StringVar(&untilText, "until", "", "next local clock time")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "guardrail: night on takes only --for or --until")
		return 2
	}
	if set["for"] && set["until"] {
		fmt.Fprintln(stderr, "guardrail: night on accepts only one of --for and --until")
		return 2
	}
	if set["for"] && durationText == "" || set["until"] && untilText == "" {
		fmt.Fprintln(stderr, "guardrail: night expiry flag cannot be empty")
		return 2
	}

	now := time.Now()
	until := now.Add(defaultNightDuration)
	if set["for"] {
		duration, err := time.ParseDuration(durationText)
		if err != nil || duration <= 0 {
			fmt.Fprintln(stderr, "guardrail: --for must be a positive duration")
			return 2
		}
		until = now.Add(duration)
	}
	if set["until"] {
		clock, err := time.ParseInLocation("15:04", untilText, now.Location())
		if err != nil {
			fmt.Fprintln(stderr, "guardrail: --until must be a local time in HH:MM format")
			return 2
		}
		until = time.Date(now.Year(), now.Month(), now.Day(), clock.Hour(), clock.Minute(), 0, 0, now.Location())
		if !until.After(now) {
			until = until.AddDate(0, 0, 1)
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nightError(fmt.Errorf("resolving hostname: %w", err), stderr)
	}
	marker := night.Marker{
		Until: until,
		SetBy: fmt.Sprintf("%s:%d", hostname, os.Getpid()),
	}
	if err := night.Write(path, marker); err != nil {
		return nightError(err, stderr)
	}
	fmt.Fprintln(stdout, (night.State{Marker: marker, Active: true}).Banner())
	return 0
}

func repeatedNightFlag(args []string, name string) bool {
	prefix := "--" + name
	count := 0
	for _, arg := range args {
		if arg == prefix || len(arg) > len(prefix) && arg[:len(prefix)+1] == prefix+"=" {
			count++
		}
	}
	return count > 1
}

func nightError(err error, stderr io.Writer) int {
	fmt.Fprintf(stderr, "guardrail: night: %s\n", safetext.SingleLine(err.Error()))
	return 2
}
