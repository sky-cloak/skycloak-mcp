package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

const defaultLogLimit = 50

func registerObservabilityReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_logs",
		Description: "Read recent Keycloak server logs for a cluster, optionally filtered by level and a search string.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get logs"},
	}, getLogsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_security_logs",
		Description: "Read recent security (WAF) logs for a cluster — blocked requests, attack types, source IPs.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get security logs"},
	}, getSecurityLogsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_query_events",
		Description: "Query Keycloak user and admin events for a cluster (logins, token grants, admin operations), filterable by category, realm, username and search.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Query events"},
	}, queryEventsHandler(api))
}

// GetLogsInput is the input schema for skycloak_get_logs.
type GetLogsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Level     string `json:"level,omitempty" jsonschema:"filter by log level (e.g. ERROR, WARN, INFO)"`
	Search    string `json:"search,omitempty" jsonschema:"free-text search"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max entries to return (default 50)"`
}

// LogsOutput is the structured result for log queries.
type LogsOutput struct {
	Logs  []skycloak.LogEntry `json:"logs"`
	Count int                 `json:"count"`
}

func getLogsHandler(api API) mcp.ToolHandlerFor[GetLogsInput, LogsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in GetLogsInput) (*mcp.CallToolResult, LogsOutput, error) {
		if in.ClusterID == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id is required"}}}, LogsOutput{}, nil
		}
		limit := in.Limit
		if limit <= 0 {
			limit = defaultLogLimit
		}
		logs, err := api.GetLogs(ctx, in.ClusterID, skycloak.LogQuery{Limit: limit, Level: in.Level, Search: in.Search})
		if err != nil {
			return toolError(err), LogsOutput{}, nil
		}
		var b strings.Builder
		for _, l := range logs {
			fmt.Fprintf(&b, "%s [%s] %s: %s\n", l.Timestamp, l.Level, l.Category, l.Message)
		}
		if len(logs) == 0 {
			b.WriteString("No log entries matched.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, LogsOutput{Logs: logs, Count: len(logs)}, nil
	}
}

// GetSecurityLogsInput is the input schema for skycloak_get_security_logs.
type GetSecurityLogsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Search    string `json:"search,omitempty" jsonschema:"free-text search"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max entries to return (default 50)"`
}

// SecurityLogsOutput is the structured result.
type SecurityLogsOutput struct {
	Logs  []skycloak.SecurityLogEntry `json:"logs"`
	Count int                         `json:"count"`
}

func getSecurityLogsHandler(api API) mcp.ToolHandlerFor[GetSecurityLogsInput, SecurityLogsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in GetSecurityLogsInput) (*mcp.CallToolResult, SecurityLogsOutput, error) {
		if in.ClusterID == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id is required"}}}, SecurityLogsOutput{}, nil
		}
		limit := in.Limit
		if limit <= 0 {
			limit = defaultLogLimit
		}
		logs, err := api.GetSecurityLogs(ctx, in.ClusterID, skycloak.SecurityLogQuery{Limit: limit, Search: in.Search})
		if err != nil {
			return toolError(err), SecurityLogsOutput{}, nil
		}
		var b strings.Builder
		for _, l := range logs {
			fmt.Fprintf(&b, "%s %s %s %s %s — %s\n", l.Timestamp, l.Action, l.Type, l.SourceIP, l.Method, l.Message)
		}
		if len(logs) == 0 {
			b.WriteString("No security log entries matched.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, SecurityLogsOutput{Logs: logs, Count: len(logs)}, nil
	}
}

// QueryEventsInput is the input schema for skycloak_query_events.
type QueryEventsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Category  string `json:"category,omitempty" jsonschema:"event category: user or admin"`
	Realm     string `json:"realm,omitempty" jsonschema:"filter by realm name"`
	Username  string `json:"username,omitempty" jsonschema:"filter by username"`
	Search    string `json:"search,omitempty" jsonschema:"free-text search"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max events to return (default 50)"`
}

// EventsOutput is the structured result.
type EventsOutput struct {
	Events []skycloak.EventEntry `json:"events"`
	Count  int                   `json:"count"`
}

func queryEventsHandler(api API) mcp.ToolHandlerFor[QueryEventsInput, EventsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in QueryEventsInput) (*mcp.CallToolResult, EventsOutput, error) {
		if in.ClusterID == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id is required"}}}, EventsOutput{}, nil
		}
		limit := in.Limit
		if limit <= 0 {
			limit = defaultLogLimit
		}
		events, err := api.QueryEvents(ctx, in.ClusterID, skycloak.EventQuery{Limit: limit, Category: in.Category, Realm: in.Realm, Username: in.Username, Search: in.Search})
		if err != nil {
			return toolError(err), EventsOutput{}, nil
		}
		var b strings.Builder
		for _, e := range events {
			fmt.Fprintf(&b, "%s [%s] %s realm=%s user=%s%s\n", e.Timestamp, e.Category, e.Type, e.RealmName, e.Username, errSuffix(e.Error))
		}
		if len(events) == 0 {
			b.WriteString("No events matched.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, EventsOutput{Events: events, Count: len(events)}, nil
	}
}

func errSuffix(e string) string {
	if e == "" {
		return ""
	}
	return " error=" + e
}
