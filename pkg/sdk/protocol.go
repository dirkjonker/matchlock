package sdk

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC request/response types
type request struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      uint64      `json:"id"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
	ID      *uint64         `json:"id,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error codes
const (
	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
	ErrCodeVMFailed       = -32000
	ErrCodeExecFailed     = -32001
	ErrCodeFileFailed     = -32002
)

// RPCError represents an error from the Matchlock RPC
type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("matchlock RPC error [%d]: %s", e.Code, e.Message)
}

// IsVMError returns true if the error is a VM-related error
func (e *RPCError) IsVMError() bool {
	return e.Code == ErrCodeVMFailed
}

// IsExecError returns true if the error is an execution error
func (e *RPCError) IsExecError() bool {
	return e.Code == ErrCodeExecFailed
}

// IsFileError returns true if the error is a file operation error
func (e *RPCError) IsFileError() bool {
	return e.Code == ErrCodeFileFailed
}

// sendRequest sends a JSON-RPC request and returns the result
func (c *Client) sendRequest(method string, params interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	id := c.requestID.Add(1)

	req := request{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      id,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	if _, err := fmt.Fprintln(c.stdin, string(data)); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read response (skip notifications)
	for {
		line, err := c.stdout.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		var resp response
		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}

		// Skip notifications (no ID)
		if resp.ID == nil {
			continue
		}

		if *resp.ID != id {
			continue
		}

		if resp.Error != nil {
			return nil, &RPCError{
				Code:    resp.Error.Code,
				Message: resp.Error.Message,
			}
		}

		return resp.Result, nil
	}
}
