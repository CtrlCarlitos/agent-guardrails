package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const codexDiagnosticTimeout = 15 * time.Second

type codexTrustMetadata struct {
	EventName   string `json:"eventName"`
	Command     string `json:"command"`
	CurrentHash string `json:"currentHash"`
	TrustStatus string `json:"trustStatus"`
	SourcePath  string `json:"sourcePath"`
}

type codexHandlerProbeResult struct {
	Started  bool
	ExitCode int
	Stderr   string
	Err      error
}

type codexRuntimeObservation struct {
	DispatchObserved bool
	Capabilities     []string
	Err              error
}

type codexConfiguredHandler struct {
	ID               string
	EventName        string
	EffectiveCommand string
}

var (
	codexTrustInspector  = inspectCodexTrust
	codexHandlerProbe    = probeCodexHandler
	codexRuntimeObserver = observeCodexRuntime
	encodedCommandRE     = regexp.MustCompile(`(?i)(?:-EncodedCommand|-enc)\s+([A-Za-z0-9+/=]+)`)
)

func printCodexHookDiagnostics(hooksPath, cwd, goos string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "codex hook diagnostics: %s\n", safetext.SingleLine(hooksPath))
	doc, handlers, err := readCodexDiagnosticHandlers(hooksPath, goos)
	if err != nil {
		fmt.Fprintln(stdout, "registered: no")
		fmt.Fprintf(stderr, "guardrail: codex hook diagnostics: %s\n", safetext.SingleLine(err.Error()))
		fmt.Fprintln(stdout, "trusted: unknown")
		fmt.Fprintln(stdout, "handler directly runnable: unknown")
		fmt.Fprintln(stdout, "runtime dispatch observed: unknown")
		fmt.Fprintln(stdout, "capabilities observed: unknown")
		fmt.Fprintln(stdout, "runtime coverage claim: none")
		return 1
	}
	registered := genconfig.CodexHooksRegistered(doc)
	fmt.Fprintf(stdout, "registered: %s\n", yesNo(registered))

	ctx, cancel := context.WithTimeout(context.Background(), codexDiagnosticTimeout)
	defer cancel()
	trust, trustErr := codexTrustInspector(ctx, cwd)
	trusted := registered && trustErr == nil
	allStarted, allFailClosed := len(handlers) > 0, len(handlers) > 0
	for _, handler := range handlers {
		fmt.Fprintf(stdout, "handler id: %s\n", safetext.SingleLine(handler.ID))
		fmt.Fprintf(stdout, "decoded effective command: %s\n", safetext.SingleLine(decodedEffectiveCommand(handler.EffectiveCommand)))
		metadata, ok := matchingCodexTrust(trust, hooksPath, handler)
		if !ok {
			trusted = false
			fmt.Fprintln(stdout, "trust status: unknown")
			fmt.Fprintln(stdout, "trust hash: unavailable")
		} else {
			fmt.Fprintf(stdout, "trust status: %s\n", safetext.SingleLine(metadata.TrustStatus))
			fmt.Fprintf(stdout, "trust hash: %s\n", safetext.SingleLine(metadata.CurrentHash))
			if metadata.TrustStatus != "trusted" && metadata.TrustStatus != "managed" {
				trusted = false
			}
		}

		probeCtx, probeCancel := context.WithTimeout(context.Background(), codexDiagnosticTimeout)
		probe := codexHandlerProbe(probeCtx, goos, handler.EffectiveCommand)
		probeCancel()
		if !probe.Started {
			allStarted = false
		}
		failClosed := probe.Started && probe.ExitCode != 0 && strings.TrimSpace(probe.Stderr) != ""
		if !failClosed {
			allFailClosed = false
		}
		if probe.Started {
			fmt.Fprintf(stdout, "direct exit code: %d\n", probe.ExitCode)
		} else {
			fmt.Fprintln(stdout, "direct exit code: unavailable")
		}
		probeStderr := strings.TrimSpace(probe.Stderr)
		if probeStderr == "" {
			probeStderr = "(empty)"
		}
		fmt.Fprintf(stdout, "direct stderr: %s\n", safetext.SingleLine(probeStderr))
		if probe.Err != nil && !probe.Started {
			fmt.Fprintf(stderr, "guardrail: codex handler %s probe: %s\n", safetext.SingleLine(handler.ID), safetext.SingleLine(probe.Err.Error()))
		}
	}
	if trustErr != nil {
		fmt.Fprintf(stderr, "guardrail: Codex trust status unavailable: %s\n", safetext.SingleLine(trustErr.Error()))
	}
	fmt.Fprintf(stdout, "trusted: %s\n", diagnosticState(trusted, trustErr != nil))
	fmt.Fprintf(stdout, "handler directly runnable: %s\n", yesNo(allStarted))
	fmt.Fprintf(stdout, "handler fail-closed: %s\n", yesNo(allFailClosed))

	observation := codexRuntimeObserver()
	if observation.Err != nil {
		fmt.Fprintln(stdout, "runtime dispatch observed: unknown")
		fmt.Fprintln(stdout, "capabilities observed: unknown")
		fmt.Fprintf(stderr, "guardrail: Codex runtime observation unavailable: %s\n", safetext.SingleLine(observation.Err.Error()))
	} else {
		if observation.DispatchObserved {
			fmt.Fprintln(stdout, "runtime dispatch observed: yes (heuristic)")
		} else {
			fmt.Fprintln(stdout, "runtime dispatch observed: no")
		}
		if len(observation.Capabilities) == 0 {
			fmt.Fprintln(stdout, "capabilities observed: none")
		} else {
			fmt.Fprintf(stdout, "capabilities observed: %s\n", safetext.SingleLine(strings.Join(observation.Capabilities, ", ")))
		}
	}
	fmt.Fprintln(stdout, "runtime coverage claim: none")
	if registered && trusted && allStarted && allFailClosed && observation.Err == nil && observation.DispatchObserved && len(observation.Capabilities) > 0 {
		return 0
	}
	return 1
}

func readCodexDiagnosticHandlers(path, goos string) (map[string]any, []codexConfiguredHandler, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	type handler struct {
		Type           string `json:"type"`
		Command        string `json:"command"`
		CommandWindows string `json:"commandWindows"`
	}
	type group struct {
		ID    string    `json:"id"`
		Hooks []handler `json:"hooks"`
	}
	var parsed struct {
		Hooks map[string][]group `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, err
	}
	var result []codexConfiguredHandler
	for _, event := range []string{"PreToolUse", "PostToolUse", "SessionStart"} {
		ownedID := "guardrail-codex-" + event
		for _, group := range parsed.Hooks[event] {
			if group.ID != ownedID {
				continue
			}
			for _, configured := range group.Hooks {
				if configured.Type != "command" {
					continue
				}
				command := configured.Command
				if goos == "windows" && configured.CommandWindows != "" {
					command = configured.CommandWindows
				}
				result = append(result, codexConfiguredHandler{ID: group.ID, EventName: event, EffectiveCommand: command})
			}
		}
	}
	if len(result) == 0 {
		return doc, nil, errors.New("no Guardrail-owned Codex command handlers")
	}
	return doc, result, nil
}

func matchingCodexTrust(entries []codexTrustMetadata, hooksPath string, handler codexConfiguredHandler) (codexTrustMetadata, bool) {
	wantEvent := map[string]string{"PreToolUse": "preToolUse", "PostToolUse": "postToolUse", "SessionStart": "sessionStart"}[handler.EventName]
	wantPath := filepath.Clean(hooksPath)
	for _, entry := range entries {
		pathMatches := filepath.Clean(entry.SourcePath) == wantPath
		if runtime.GOOS == "windows" {
			pathMatches = strings.EqualFold(filepath.Clean(entry.SourcePath), wantPath)
		}
		if pathMatches && entry.EventName == wantEvent && entry.Command == handler.EffectiveCommand {
			return entry, true
		}
	}
	return codexTrustMetadata{}, false
}

func decodedEffectiveCommand(command string) string {
	match := encodedCommandRE.FindStringSubmatch(command)
	if len(match) != 2 {
		return command
	}
	raw, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil || len(raw)%2 != 0 {
		return command + " (EncodedCommand decode failed)"
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(units))
}

func inspectCodexTrust(ctx context.Context, cwd string) ([]codexTrustMetadata, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", "codex app-server --stdio")
	} else {
		cmd = exec.CommandContext(ctx, "codex", "app-server", "--stdio")
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var processStderr cappedBuffer
	processStderr.limit = 8 << 10
	cmd.Stderr = &processStderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	enc := json.NewEncoder(stdin)
	if err := enc.Encode(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"clientInfo": map[string]string{"name": "guardrail-doctor", "version": version}, "capabilities": map[string]bool{"experimentalApi": true}}}); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	if _, err := readCodexRPCResult(scanner, 1); err != nil {
		return nil, fmt.Errorf("initialize: %w (%s)", err, strings.TrimSpace(processStderr.String()))
	}
	if err := enc.Encode(map[string]any{"method": "initialized"}); err != nil {
		return nil, err
	}
	if err := enc.Encode(map[string]any{"id": 2, "method": "hooks/list", "params": map[string]any{"cwds": []string{cwd}}}); err != nil {
		return nil, err
	}
	result, err := readCodexRPCResult(scanner, 2)
	if err != nil {
		return nil, fmt.Errorf("hooks/list: %w (%s)", err, strings.TrimSpace(processStderr.String()))
	}
	var response struct {
		Data []struct {
			Hooks []codexTrustMetadata `json:"hooks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, err
	}
	var entries []codexTrustMetadata
	for _, data := range response.Data {
		entries = append(entries, data.Hooks...)
	}
	return entries, nil
}

func readCodexRPCResult(scanner *bufio.Scanner, id int) (json.RawMessage, error) {
	for scanner.Scan() {
		var envelope struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(scanner.Bytes(), &envelope) != nil || string(envelope.ID) != fmt.Sprint(id) {
			continue
		}
		if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
			return nil, fmt.Errorf("RPC error: %s", safetext.SingleLine(string(envelope.Error)))
		}
		return envelope.Result, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.ErrUnexpectedEOF
}

func probeCodexHandler(ctx context.Context, goos, command string) codexHandlerProbeResult {
	var cmd *exec.Cmd
	if goos == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	cmd.Stdin = strings.NewReader("{}\n")
	cmd.Stdout = io.Discard
	var stderr cappedBuffer
	stderr.limit = 8 << 10
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := codexHandlerProbeResult{Stderr: stderr.String(), Err: err}
	if cmd.ProcessState != nil {
		result.Started = true
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	return result
}

func observeCodexRuntime() codexRuntimeObservation {
	binary, err := os.Executable()
	if err != nil {
		return codexRuntimeObservation{Err: err}
	}
	info, err := os.Stat(binary)
	if err != nil {
		return codexRuntimeObservation{Err: err}
	}
	segments, err := audit.Segments(audit.DefaultPath(""))
	if err != nil {
		return codexRuntimeObservation{Err: err}
	}
	evidence, err := audit.ReadCodexEvidence(segments, info.ModTime(), time.Now())
	return codexRuntimeObservation{DispatchObserved: evidence.Observed(), Capabilities: evidence.Capabilities, Err: err}
}

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
	mu    sync.Mutex
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(p)
	remaining := w.limit - w.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.buf.Write(p)
	}
	return original, nil
}

func (w *cappedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func diagnosticState(value, unknown bool) string {
	if unknown {
		return "unknown"
	}
	return yesNo(value)
}
