package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type Client struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *json.Encoder
	mu     sync.Mutex
}

func Dial(endpoint string) (*Client, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint()
	}
	conn, err := dialPrivate(endpoint)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: json.NewEncoder(conn),
	}, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

func (c *Client) Evaluate(tc engine.ToolCall) (policy.Verdict, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := Request{
		Action:   "evaluate",
		ToolCall: &tc,
	}
	if err := c.writer.Encode(req); err != nil {
		return policy.Verdict{}, fmt.Errorf("send request: %w", err)
	}

	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("read response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return policy.Verdict{}, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Status != "ok" {
		return policy.Verdict{}, fmt.Errorf("daemon error: %s", resp.Error)
	}
	if resp.Verdict == nil {
		return policy.Verdict{}, errors.New("empty verdict in daemon response")
	}
	return *resp.Verdict, nil
}

func (c *Client) Shutdown() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := Request{Action: "shutdown"}
	if err := c.writer.Encode(req); err != nil {
		return fmt.Errorf("send shutdown: %w", err)
	}

	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read shutdown response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	if resp.Status != "shutting_down" {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return nil
}

func (c *Client) Ping() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	req := Request{Action: "ping"}
	if err := c.writer.Encode(req); err != nil {
		return "", fmt.Errorf("send ping: %w", err)
	}

	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return "", fmt.Errorf("read ping response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return "", fmt.Errorf("unmarshal ping response: %w", err)
	}
	if resp.Status != "ok" {
		return "", fmt.Errorf("daemon error: %s", resp.Error)
	}
	return resp.Version, nil
}
