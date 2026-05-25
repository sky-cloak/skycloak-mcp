package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestGetLogsHandler(t *testing.T) {
	api := stubAPI{logs: []skycloak.LogEntry{{Timestamp: "t", Level: "ERROR", Category: "org.kc", Message: "boom"}}}
	res, out, err := getLogsHandler(api)(context.Background(), nil, GetLogsInput{ClusterID: "c1", Level: "ERROR"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Count != 1 || out.Logs[0].Message != "boom" {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestGetLogsHandler_MissingCluster(t *testing.T) {
	res, _, err := getLogsHandler(stubAPI{})(context.Background(), nil, GetLogsInput{})
	if err != nil || !res.IsError {
		t.Fatalf("expected IsError for missing cluster_id (err=%v)", err)
	}
}

func TestGetSecurityLogsHandler(t *testing.T) {
	api := stubAPI{secLogs: []skycloak.SecurityLogEntry{{Timestamp: "t", Type: "waf", Action: "blocked", SourceIP: "1.2.3.4"}}}
	res, out, err := getSecurityLogsHandler(api)(context.Background(), nil, GetSecurityLogsInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.Count != 1 {
		t.Fatalf("unexpected: err=%v isErr=%v out=%+v", err, res.IsError, out)
	}
}

func TestQueryEventsHandler(t *testing.T) {
	api := stubAPI{events: []skycloak.EventEntry{{Timestamp: "t", Category: "user", Type: "LOGIN", RealmName: "app", Username: "bob"}}}
	res, out, err := queryEventsHandler(api)(context.Background(), nil, QueryEventsInput{ClusterID: "c1", Category: "user"})
	if err != nil || res.IsError || out.Count != 1 || out.Events[0].Username != "bob" {
		t.Fatalf("unexpected: err=%v isErr=%v out=%+v", err, res.IsError, out)
	}
}

func TestQueryEventsHandler_MissingCluster(t *testing.T) {
	res, _, err := queryEventsHandler(stubAPI{})(context.Background(), nil, QueryEventsInput{})
	if err != nil || !res.IsError {
		t.Fatalf("expected IsError for missing cluster_id (err=%v)", err)
	}
}
