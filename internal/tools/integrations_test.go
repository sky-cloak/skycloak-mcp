package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestCAPTCHADomainHandlers(t *testing.T) {
	res, out, err := listClusterCAPTCHADomainsHandler(stubAPI{})(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.Count != 1 || out.MaxAllowed != 10 {
		t.Fatalf("list captcha domains: err=%v res=%v out=%+v", err, res.IsError, out)
	}

	res, domain, err := addClusterCAPTCHADomainHandler(stubAPI{})(context.Background(), nil, CAPTCHADomainInput{ClusterID: "c1", Hostname: "login.example.com"})
	if err != nil || res.IsError || domain.Hostname != "login.example.com" {
		t.Fatalf("add captcha domain: err=%v res=%v out=%+v", err, res.IsError, domain)
	}

	if res, _, _ := removeClusterCAPTCHADomainHandler(stubAPI{})(context.Background(), nil, RemoveCAPTCHADomainInput{ClusterID: "c1", Hostname: "login.example.com"}); !res.IsError {
		t.Fatalf("remove captcha domain should require confirm")
	}
}

func TestSIEMHandlers(t *testing.T) {
	res, out, err := listSIEMDestinationsHandler(stubAPI{})(context.Background(), nil, NoInput{})
	if err != nil || res.IsError || out.Count != 1 {
		t.Fatalf("list siem: err=%v res=%v out=%+v", err, res.IsError, out)
	}

	res, created, err := createSIEMDestinationHandler(stubAPI{})(context.Background(), nil, skycloak.CreateSIEMDestinationRequest{Name: "splunk", Type: "http", Source: skycloak.SIEMSourceConfig{Type: "skycloak_audit"}})
	if err != nil || res.IsError || created.Name != "splunk" {
		t.Fatalf("create siem: err=%v res=%v out=%+v", err, res.IsError, created)
	}

	if res, _, _ := deleteSIEMDestinationHandler(stubAPI{})(context.Background(), nil, DestinationConfirmInput{DestinationID: "d1"}); !res.IsError {
		t.Fatalf("delete siem should require confirm")
	}
}

func TestWebhookHandlers(t *testing.T) {
	res, events, err := listWebhookEventTypesHandler(stubAPI{})(context.Background(), nil, WebhookEventTypesInput{})
	if err != nil || res.IsError || events.Count != 1 {
		t.Fatalf("list webhook event types: err=%v res=%v out=%+v", err, res.IsError, events)
	}

	res, created, err := createWebhookSubscriptionHandler(stubAPI{})(context.Background(), nil, skycloak.CreateWebhookSubscriptionRequest{Name: "ops", URL: "https://hooks.example.com", Source: "platform", SigningSecret: "secret", EventTypes: []string{"cluster.created"}})
	if err != nil || res.IsError || created.Name != "ops" {
		t.Fatalf("create webhook: err=%v res=%v out=%+v", err, res.IsError, created)
	}

	if res, _, _ := deleteWebhookSubscriptionHandler(stubAPI{})(context.Background(), nil, WebhookConfirmInput{WebhookID: "w1"}); !res.IsError {
		t.Fatalf("delete webhook should require confirm")
	}
}
