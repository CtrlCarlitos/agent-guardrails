package daemon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type EvaluatorFunc func(engine.ToolCall) (policy.Verdict, error)

type ServerConfig struct {
	Endpoint    string
	Evaluator   EvaluatorFunc
	IdleTimeout time.Duration
	BinaryPath  string
}

type Server struct {
	cfg         ServerConfig
	listener    net.Listener
	shutdownCh  chan struct{}
	activityCh  chan struct{}
	once        sync.Once
	initialHash []byte
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultEndpoint()
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 30 * time.Minute
	}
	l, err := listenPrivate(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	var hash []byte
	if cfg.BinaryPath != "" {
		if raw, err := os.ReadFile(cfg.BinaryPath); err == nil {
			sum := sha256.Sum256(raw)
			hash = sum[:]
		}
	}

	return &Server{
		cfg:         cfg,
		listener:    l,
		shutdownCh:  make(chan struct{}),
		activityCh:  make(chan struct{}, 10),
		initialHash: hash,
	}, nil
}

func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.shutdownCh)
	})
	return s.listener.Close()
}

func (s *Server) Serve(ctx context.Context) error {
	idleTimer := time.NewTimer(s.cfg.IdleTimeout)
	defer idleTimer.Stop()

	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.shutdownCh:
			_ = s.Close()
		}
	}()

	// Background idle monitor & image hash check
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.shutdownCh:
				return
			case <-s.activityCh:
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(s.cfg.IdleTimeout)
			case <-idleTimer.C:
				// Idle timeout reached
				_ = s.Close()
				return
			case <-ticker.C:
				// Check if binary image was replaced on disk
				if s.binaryReplaced() {
					_ = s.Close()
					return
				}
			}
		}
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return ErrServerClosed
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}

		select {
		case s.activityCh <- struct{}{}:
		default:
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) binaryReplaced() bool {
	if s.cfg.BinaryPath == "" || len(s.initialHash) == 0 {
		return false
	}
	raw, err := os.ReadFile(s.cfg.BinaryPath)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return !equalBytes(sum[:], s.initialHash)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := verifyClientToken(conn); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{
			Status: "error",
			Error:  fmt.Sprintf("client verification failed: %v", err),
		})
		return
	}

	reader := bufio.NewReader(conn)
	writer := json.NewEncoder(conn)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			return
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = writer.Encode(Response{
				Status: "error",
				Error:  ErrMalformedRequest.Error(),
			})
			return
		}

		switch req.Action {
		case "shutdown":
			_ = writer.Encode(Response{Status: "shutting_down"})
			_ = s.Close()
			return
		case "ping":
			_ = writer.Encode(Response{Status: "ok", Version: "1.0.0"})
		case "evaluate":
			if req.ToolCall == nil {
				_ = writer.Encode(Response{Status: "error", Error: "missing tool_call"})
				return
			}
			verdict, err := s.cfg.Evaluator(*req.ToolCall)
			if err != nil {
				_ = writer.Encode(Response{Status: "error", Error: err.Error()})
				return
			}
			_ = writer.Encode(Response{Status: "ok", Verdict: &verdict})
		default:
			_ = writer.Encode(Response{Status: "error", Error: "unknown action"})
			return
		}
	}
}
