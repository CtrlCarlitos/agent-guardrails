package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestDaemonEvaluateEchoRoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	endpoint := TestEndpoint(t, tempDir)

	evaluator := func(tc engine.ToolCall) (policy.Verdict, error) {
		if tc.Tool == "todowrite" {
			return policy.Verdict{Decision: policy.Allow}, nil
		}
		return policy.Verdict{Decision: policy.Deny, RuleID: "P1.test-deny"}, nil
	}

	server, err := NewServer(ServerConfig{
		Endpoint:    endpoint,
		Evaluator:   evaluator,
		IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	// Wait for server to start listening
	time.Sleep(100 * time.Millisecond)

	client, err := Dial(endpoint)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer client.Close()

	// 1. Evaluate tool call
	tc := engine.ToolCall{Tool: "todowrite", SessionID: "sess-1", Event: "pre"}
	v, err := client.Evaluate(tc)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if v.Decision != policy.Allow {
		t.Errorf("got decision %v, want allow", v.Decision)
	}

	// 2. Denied tool call
	denyTc := engine.ToolCall{Tool: "dangerous_cmd", SessionID: "sess-1", Event: "pre"}
	v2, err := client.Evaluate(denyTc)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if v2.Decision != policy.Deny || v2.RuleID != "P1.test-deny" {
		t.Errorf("got verdict %+v, want deny/P1.test-deny", v2)
	}

	// 3. Graceful shutdown
	if err := client.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && err != ErrServerClosed && err != context.Canceled {
			t.Errorf("Serve exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestDaemonIdleTimeout(t *testing.T) {
	tempDir := t.TempDir()
	endpoint := TestEndpoint(t, tempDir)

	server, err := NewServer(ServerConfig{
		Endpoint:    endpoint,
		Evaluator:   func(tc engine.ToolCall) (policy.Verdict, error) { return policy.Verdict{Decision: policy.Allow}, nil },
		IdleTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	select {
	case err := <-errCh:
		if err != nil && err != ErrServerClosed {
			t.Errorf("expected clean server closed, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle timeout did not trigger server shutdown")
	}
}

func TestDaemonAlreadyRunningRefusal(t *testing.T) {
	tempDir := t.TempDir()
	endpoint := TestEndpoint(t, tempDir)

	s1, err := NewServer(ServerConfig{
		Endpoint:    endpoint,
		Evaluator:   func(tc engine.ToolCall) (policy.Verdict, error) { return policy.Verdict{Decision: policy.Allow}, nil },
		IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("first NewServer failed: %v", err)
	}
	defer s1.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s1.Serve(ctx) }()

	time.Sleep(100 * time.Millisecond)

	// Second server on same endpoint must fail
	_, err = NewServer(ServerConfig{
		Endpoint:    endpoint,
		Evaluator:   func(tc engine.ToolCall) (policy.Verdict, error) { return policy.Verdict{Decision: policy.Allow}, nil },
		IdleTimeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("second NewServer on same endpoint succeeded, want error")
	}
}
