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
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get logs"},
	}, getLogsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_security_logs",
		Description: "Read recent security (WAF) logs for a cluster — blocked requests, attack types, source IPs.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get security logs"},
	}, getSecurityLogsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_query_events",
		Description: queryEventsDescription,
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Query events"},
	}, queryEventsHandler(api))
}

// GetLogsInput is the input schema for skycloak_get_logs.
type GetLogsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Level     string `json:"level,omitempty" jsonschema:"filter by log level: info, warn, error, or debug (case-insensitive)"`
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
		logs, err := api.GetLogs(ctx, in.ClusterID, skycloak.LogQuery{Limit: limit, Level: enumLogLevel.canonical(in.Level), Search: in.Search})
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

// queryEventsDescription spells out what search does and does not cover. It read
// as "free-text search" before, which invites the assumption that it matches the
// event type; it never has, so a caller filtering for LOGIN_ERROR that way gets
// zero results for a realm that has them, and reads that as "no failed logins".
const queryEventsDescription = "Query Keycloak user and admin events for a cluster (logins, token grants, admin operations). " +
	"Filter user events with types/error, admin events with operation_types, and either with realm, start_time/end_time, and offset. " +
	"Note search only matches username, client_id, realm_name and ip_address; it does not match the event type, so use types or operation_types for that. " +
	"Limit is capped at 100 per call, so page with offset for anything larger."

// QueryEventsInput is the input schema for skycloak_query_events.
type QueryEventsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Category  string `json:"category,omitempty" jsonschema:"event category: user or admin (case-insensitive)"`
	Realm     string `json:"realm,omitempty" jsonschema:"filter by realm name"`
	Username  string `json:"username,omitempty" jsonschema:"filter by username"`
	Search    string `json:"search,omitempty" jsonschema:"substring match over username, client_id, realm_name and ip_address only; does NOT match event type"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max events to return (default 50, max 100)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"number of events to skip, for paging past the 100-per-call cap"`

	StartTime string `json:"start_time,omitempty" jsonschema:"inclusive start time, RFC3339. Without it the API only covers the last 24 hours"`
	EndTime   string `json:"end_time,omitempty" jsonschema:"inclusive end time, RFC3339"`

	Types          []string `json:"types,omitempty" jsonschema:"user event types to match, e.g. LOGIN, LOGIN_ERROR, LOGOUT, REGISTER (case-insensitive). User events only"`
	OperationTypes []string `json:"operation_types,omitempty" jsonschema:"admin operation types to match: CREATE, UPDATE, DELETE or ACTION (case-insensitive). Admin events only"`
	Error          string   `json:"error,omitempty" jsonschema:"filter user events by Keycloak error code, e.g. invalid_user_credentials"`
	Order          string   `json:"order,omitempty" jsonschema:"timestamp sort order: asc or desc (case-insensitive, default desc)"`
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
		category := enumEventCategory.canonical(in.Category)
		events, err := api.QueryEvents(ctx, in.ClusterID, skycloak.EventQuery{
			Limit: limit, Offset: in.Offset, Category: category,
			Realm: in.Realm, Username: in.Username, Search: in.Search,
			StartTime: in.StartTime, EndTime: in.EndTime,
			Types:          canonicalEach(enumUserEventType, in.Types),
			OperationTypes: canonicalEach(enumAdminOperationType, in.OperationTypes),
			Error:          in.Error, Order: enumSortOrder.canonical(in.Order),
		})
		if err != nil {
			return toolError(err), EventsOutput{}, nil
		}
		if events == nil {
			events = []skycloak.EventEntry{}
		}
		var b strings.Builder
		for _, e := range events {
			fmt.Fprintf(&b, "%s [%s] %s realm=%s user=%s%s%s\n", e.Timestamp, e.Category, e.Type, e.RealmName, e.Username, resourceSuffix(e), errSuffix(e.Error))
		}
		if len(events) == 0 {
			b.WriteString("No events matched.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, EventsOutput{Events: events, Count: len(events)}, nil
	}
}

// resourceSuffix names what an admin event acted on. Without it every admin
// UPDATE renders identically, whether it changed realm login settings, a user,
// or a client, which is exactly the question operators ask of an audit trail.
func resourceSuffix(e skycloak.EventEntry) string {
	switch {
	case e.ResourceType != "" && e.ResourcePath != "":
		return " resource=" + e.ResourceType + " path=" + e.ResourcePath
	case e.ResourceType != "":
		return " resource=" + e.ResourceType
	case e.ResourcePath != "":
		return " path=" + e.ResourcePath
	default:
		return ""
	}
}

func errSuffix(e string) string {
	if e == "" {
		return ""
	}
	return " error=" + e
}
