// Package mcp exposes the vigilo event buffer over the Model Context Protocol.
// The daemon runs as an MCP server; the vigilo-agent (TypeScript) is the client.
// Any MCP-compatible client — including Claude Desktop — can connect directly
// to investigate events interactively.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
)

// Server wraps the MCP server and exposes query tools over the event buffer.
type Server struct {
	store    *buffer.Store
	mcpSrv   *server.MCPServer
	handlers map[string]server.ToolHandlerFunc
}

func New(store *buffer.Store) *Server {
	s := &Server{
		store:    store,
		handlers: make(map[string]server.ToolHandlerFunc),
	}
	s.mcpSrv = server.NewMCPServer("vigilo", "0.1.0",
		server.WithToolCapabilities(true),
	)
	s.registerTools()
	return s
}

// CallTool invokes a registered tool by name. Used in tests and direct callers.
func (s *Server) CallTool(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	h, ok := s.handlers[req.Params.Name]
	if !ok {
		return nil, fmt.Errorf("tool %q not found", req.Params.Name)
	}
	return h(ctx, req)
}

// ServeStdio runs the MCP server over stdin/stdout (default transport).
func (s *Server) ServeStdio(ctx context.Context) error {
	return server.ServeStdio(s.mcpSrv)
}

// ServeSSE runs the MCP server over SSE (HTTP transport for remote agents).
func (s *Server) ServeSSE(addr string) error {
	sse := server.NewSSEServer(s.mcpSrv, server.WithBaseURL("http://"+addr))
	return sse.Start(addr)
}

func (s *Server) addTool(tool mcp.Tool, h server.ToolHandlerFunc) {
	s.mcpSrv.AddTool(tool, h)
	s.handlers[tool.Name] = h
}

func (s *Server) registerTools() {
	s.addTool(mcp.NewTool("get_file_access_events",
		mcp.WithDescription("Return file access events for sensitive paths (keystores, .env, private keys) in the given time window."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp — return events after this time")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 100)")),
		mcp.WithString("severity", mcp.Description("Minimum severity: info|medium|high|critical")),
	), s.handleFileEvents)

	s.addTool(mcp.NewTool("get_process_events",
		mcp.WithDescription("Return suspicious process spawn events (e.g. shell spawned from node, curl from python)."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 100)")),
	), s.handleProcessEvents)

	s.addTool(mcp.NewTool("get_network_events",
		mcp.WithDescription("Return outbound network connection events to unexpected or suspicious destinations."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 100)")),
		mcp.WithString("severity", mcp.Description("Minimum severity: info|medium|high|critical")),
	), s.handleNetworkEvents)

	s.addTool(mcp.NewTool("get_all_events",
		mcp.WithDescription("Return all events across all sources in the given window. Use for correlation analysis."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
		mcp.WithNumber("limit", mcp.Description("Max events to return (default 200)")),
		mcp.WithString("severity", mcp.Description("Minimum severity filter")),
	), s.handleAllEvents)

	s.addTool(mcp.NewTool("get_critical_events",
		mcp.WithDescription("Return only critical and high severity events. Use for rapid triage."),
		mcp.WithString("since", mcp.Required(), mcp.Description("ISO8601 timestamp")),
	), s.handleCriticalEvents)
}

func parseSince(args map[string]any) time.Time {
	sinceStr, _ := args["since"].(string)
	if sinceStr == "" {
		return time.Now().Add(-time.Hour)
	}
	t, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil {
		return time.Now().Add(-time.Hour)
	}
	return t
}

func parseLimit(args map[string]any, def int) int {
	if v, ok := args["limit"].(float64); ok && v > 0 {
		return int(v)
	}
	return def
}

func parseSeverity(args map[string]any) string {
	if v, ok := args["severity"].(string); ok {
		return v
	}
	return ""
}

func errorResult(msg string) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultText(fmt.Sprintf(`{"error":%q}`, msg)), nil
}

func (s *Server) queryAndRespond(opts buffer.QueryOptions) (*mcp.CallToolResult, error) {
	events, err := s.store.List(opts)
	if err != nil {
		return errorResult(fmt.Sprintf("query error: %v", err))
	}
	if events == nil {
		events = []collector.Event{}
	}
	b, err := json.Marshal(events)
	if err != nil {
		return errorResult("serialization error")
	}
	return mcp.NewToolResultText(string(b)), nil
}

func (s *Server) handleFileEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    parseSince(req.Params.Arguments),
		Sources:  []string{string(collector.SourceFile)},
		Severity: parseSeverity(req.Params.Arguments),
		Limit:    parseLimit(req.Params.Arguments, 100),
	})
}

func (s *Server) handleProcessEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.queryAndRespond(buffer.QueryOptions{
		Since:   parseSince(req.Params.Arguments),
		Sources: []string{string(collector.SourceProcess)},
		Limit:   parseLimit(req.Params.Arguments, 100),
	})
}

func (s *Server) handleNetworkEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    parseSince(req.Params.Arguments),
		Sources:  []string{string(collector.SourceNetwork)},
		Severity: parseSeverity(req.Params.Arguments),
		Limit:    parseLimit(req.Params.Arguments, 100),
	})
}

func (s *Server) handleAllEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    parseSince(req.Params.Arguments),
		Severity: parseSeverity(req.Params.Arguments),
		Limit:    parseLimit(req.Params.Arguments, 200),
	})
}

func (s *Server) handleCriticalEvents(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return s.queryAndRespond(buffer.QueryOptions{
		Since:    parseSince(req.Params.Arguments),
		Severity: "high",
		Limit:    50,
	})
}
