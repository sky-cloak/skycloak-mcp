package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerSIEMReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_list_siem_destinations", Description: "List SIEM destinations configured for the workspace.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "List SIEM destinations"}}, listSIEMDestinationsHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_get_siem_destination", Description: "Get a SIEM destination by ID.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get SIEM destination"}}, getSIEMDestinationHandler(api))
}

func registerSIEMWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_create_siem_destination", Description: "Create a SIEM destination. Credentials are write-only and are not returned.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create SIEM destination"}}, createSIEMDestinationHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_siem_destination", Description: "Update a SIEM destination. Only provided fields are changed; credentials remain write-only.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Update SIEM destination"}}, updateSIEMDestinationHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_delete_siem_destination", Description: "Delete a SIEM destination. Set confirm=true to proceed.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete SIEM destination"}}, deleteSIEMDestinationHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_test_siem_destination", Description: "Send a test event to a SIEM destination.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Test SIEM destination"}}, testSIEMDestinationHandler(api))
}

func registerWebhookReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_list_webhook_event_types", Description: "List webhook event types. Optionally filter by source: platform or keycloak.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "List webhook event types"}}, listWebhookEventTypesHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_list_webhook_subscriptions", Description: "List webhook subscriptions. Optionally filter by source, cluster_id, and enabled.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "List webhook subscriptions"}}, listWebhookSubscriptionsHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_get_webhook_subscription", Description: "Get a webhook subscription by ID.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get webhook subscription"}}, getWebhookSubscriptionHandler(api))
}

func registerWebhookWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_create_webhook_subscription", Description: "Create a webhook subscription. Signing secrets and authorization headers are write-only.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create webhook subscription"}}, createWebhookSubscriptionHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_webhook_subscription", Description: "Update a webhook subscription. Use clear_authorization_header, clear_cluster_id, or clear_realm_id to remove nullable fields.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Update webhook subscription"}}, updateWebhookSubscriptionHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_delete_webhook_subscription", Description: "Delete a webhook subscription. Set confirm=true to proceed.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete webhook subscription"}}, deleteWebhookSubscriptionHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_test_webhook_subscription", Description: "Send a test event to a webhook subscription.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Test webhook subscription"}}, testWebhookSubscriptionHandler(api))
}

// SIEMDestinationsOutput is the structured list result for SIEM destinations.
type SIEMDestinationsOutput struct {
	Destinations []skycloak.SIEMDestination `json:"destinations"`
	Count        int                        `json:"count"`
}

func listSIEMDestinationsHandler(api API) mcp.ToolHandlerFor[NoInput, SIEMDestinationsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ NoInput) (*mcp.CallToolResult, SIEMDestinationsOutput, error) {
		destinations, err := api.ListSIEMDestinations(ctx)
		if err != nil {
			return toolError(err), SIEMDestinationsOutput{}, nil
		}
		var b strings.Builder
		for _, d := range destinations {
			fmt.Fprintf(&b, "- %s (%s) type=%s enabled=%t health=%s\n", d.Name, d.ID, d.Type, d.Enabled, d.HealthStatus)
		}
		if len(destinations) == 0 {
			b.WriteString("No SIEM destinations configured.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, SIEMDestinationsOutput{Destinations: destinations, Count: len(destinations)}, nil
	}
}

// DestinationRef identifies a SIEM destination.
type DestinationRef struct {
	DestinationID string `json:"destination_id" jsonschema:"the SIEM destination ID"`
}

func getSIEMDestinationHandler(api API) mcp.ToolHandlerFor[DestinationRef, skycloak.SIEMDestination] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DestinationRef) (*mcp.CallToolResult, skycloak.SIEMDestination, error) {
		if in.DestinationID == "" {
			return errResult("destination_id is required"), skycloak.SIEMDestination{}, nil
		}
		d, err := api.GetSIEMDestination(ctx, in.DestinationID)
		if err != nil {
			return toolError(err), skycloak.SIEMDestination{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: siemText(d)}}}, *d, nil
	}
}

func createSIEMDestinationHandler(api API) mcp.ToolHandlerFor[skycloak.CreateSIEMDestinationRequest, skycloak.SIEMDestination] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in skycloak.CreateSIEMDestinationRequest) (*mcp.CallToolResult, skycloak.SIEMDestination, error) {
		if in.Name == "" || in.Type == "" || in.Source.Type == "" {
			return errResult("name, type and source.type are required"), skycloak.SIEMDestination{}, nil
		}
		in.Type = enumSIEMDestinationType.canonical(in.Type)
		normaliseSIEMSource(&in.Source)
		normaliseSIEMTransport(in.Syslog, in.S3, in.HTTP)
		d, err := api.CreateSIEMDestination(ctx, in)
		if err != nil {
			return toolError(err), skycloak.SIEMDestination{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Created " + siemText(d)}}}, *d, nil
	}
}

// UpdateSIEMDestinationInput is the input for skycloak_update_siem_destination.
type UpdateSIEMDestinationInput struct {
	DestinationID string `json:"destination_id" jsonschema:"the SIEM destination ID"`
	skycloak.UpdateSIEMDestinationRequest
}

func updateSIEMDestinationHandler(api API) mcp.ToolHandlerFor[UpdateSIEMDestinationInput, skycloak.SIEMDestination] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateSIEMDestinationInput) (*mcp.CallToolResult, skycloak.SIEMDestination, error) {
		if in.DestinationID == "" {
			return errResult("destination_id is required"), skycloak.SIEMDestination{}, nil
		}
		normaliseSIEMSource(in.Source)
		normaliseSIEMTransport(in.Syslog, in.S3, in.HTTP)
		d, err := api.UpdateSIEMDestination(ctx, in.DestinationID, in.UpdateSIEMDestinationRequest)
		if err != nil {
			return toolError(err), skycloak.SIEMDestination{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated " + siemText(d)}}}, *d, nil
	}
}

// DestinationConfirmInput confirms a SIEM destination deletion.
type DestinationConfirmInput struct {
	DestinationID string `json:"destination_id" jsonschema:"the SIEM destination ID"`
	Confirm       bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteSIEMDestinationHandler(api API) mcp.ToolHandlerFor[DestinationConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DestinationConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.DestinationID == "" {
			return errResult("destination_id is required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete SIEM destination %s: set confirm=true.", in.DestinationID)), struct{}{}, nil
		}
		if err := api.DeleteSIEMDestination(ctx, in.DestinationID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Deleted SIEM destination %s.", in.DestinationID)}}}, struct{}{}, nil
	}
}

func testSIEMDestinationHandler(api API) mcp.ToolHandlerFor[DestinationRef, skycloak.SIEMDestinationTestResult] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DestinationRef) (*mcp.CallToolResult, skycloak.SIEMDestinationTestResult, error) {
		if in.DestinationID == "" {
			return errResult("destination_id is required"), skycloak.SIEMDestinationTestResult{}, nil
		}
		out, err := api.TestSIEMDestination(ctx, in.DestinationID)
		if err != nil {
			return toolError(err), skycloak.SIEMDestinationTestResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("SIEM destination test success=%t %s", out.Success, out.Message)}}}, *out, nil
	}
}

func siemText(d *skycloak.SIEMDestination) string {
	return fmt.Sprintf("SIEM destination %q (%s) type=%s enabled=%t health=%s", d.Name, d.ID, d.Type, d.Enabled, d.HealthStatus)
}

// WebhookEventTypesInput filters webhook event types.
type WebhookEventTypesInput struct {
	Source string `json:"source,omitempty" jsonschema:"optional source filter: keycloak or platform (case-insensitive)"`
}

// WebhookEventTypesOutput is the structured list result for webhook event types.
type WebhookEventTypesOutput struct {
	EventTypes []skycloak.WebhookEventType `json:"event_types"`
	Count      int                         `json:"count"`
}

func listWebhookEventTypesHandler(api API) mcp.ToolHandlerFor[WebhookEventTypesInput, WebhookEventTypesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in WebhookEventTypesInput) (*mcp.CallToolResult, WebhookEventTypesOutput, error) {
		events, err := api.ListWebhookEventTypes(ctx, enumWebhookSource.canonical(in.Source))
		if err != nil {
			return toolError(err), WebhookEventTypesOutput{}, nil
		}
		var b strings.Builder
		for _, e := range events {
			fmt.Fprintf(&b, "- %s (%s) deprecated=%t\n", e.Type, e.Category, e.Deprecated)
		}
		if len(events) == 0 {
			b.WriteString("No webhook event types found.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, WebhookEventTypesOutput{EventTypes: events, Count: len(events)}, nil
	}
}

// WebhookSubscriptionsOutput is the structured list result for webhook subscriptions.
type WebhookSubscriptionsOutput struct {
	Subscriptions []skycloak.WebhookSubscription `json:"subscriptions"`
	Count         int                            `json:"count"`
}

func listWebhookSubscriptionsHandler(api API) mcp.ToolHandlerFor[skycloak.ListWebhookSubscriptionsFilter, WebhookSubscriptionsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in skycloak.ListWebhookSubscriptionsFilter) (*mcp.CallToolResult, WebhookSubscriptionsOutput, error) {
		in.Source = enumWebhookSource.canonical(in.Source)
		hooks, err := api.ListWebhookSubscriptions(ctx, in)
		if err != nil {
			return toolError(err), WebhookSubscriptionsOutput{}, nil
		}
		var b strings.Builder
		for _, h := range hooks {
			fmt.Fprintf(&b, "- %s (%s) source=%s enabled=%t events=%d\n", h.Name, h.ID, h.Source, h.Enabled, len(h.EventTypes))
		}
		if len(hooks) == 0 {
			b.WriteString("No webhook subscriptions configured.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, WebhookSubscriptionsOutput{Subscriptions: hooks, Count: len(hooks)}, nil
	}
}

// WebhookRef identifies a webhook subscription.
type WebhookRef struct {
	WebhookID string `json:"webhook_id" jsonschema:"the webhook subscription ID"`
}

func getWebhookSubscriptionHandler(api API) mcp.ToolHandlerFor[WebhookRef, skycloak.WebhookSubscription] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in WebhookRef) (*mcp.CallToolResult, skycloak.WebhookSubscription, error) {
		if in.WebhookID == "" {
			return errResult("webhook_id is required"), skycloak.WebhookSubscription{}, nil
		}
		h, err := api.GetWebhookSubscription(ctx, in.WebhookID)
		if err != nil {
			return toolError(err), skycloak.WebhookSubscription{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: webhookText(h)}}}, *h, nil
	}
}

func createWebhookSubscriptionHandler(api API) mcp.ToolHandlerFor[skycloak.CreateWebhookSubscriptionRequest, skycloak.WebhookSubscription] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in skycloak.CreateWebhookSubscriptionRequest) (*mcp.CallToolResult, skycloak.WebhookSubscription, error) {
		if in.Name == "" || in.URL == "" || in.Source == "" || in.SigningSecret == "" || len(in.EventTypes) == 0 {
			return errResult("name, url, source, signing_secret and event_types are required"), skycloak.WebhookSubscription{}, nil
		}
		in.Source = enumWebhookSource.canonical(in.Source)
		h, err := api.CreateWebhookSubscription(ctx, in)
		if err != nil {
			return toolError(err), skycloak.WebhookSubscription{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Created " + webhookText(h)}}}, *h, nil
	}
}

// UpdateWebhookSubscriptionInput is the input for skycloak_update_webhook_subscription.
type UpdateWebhookSubscriptionInput struct {
	WebhookID string `json:"webhook_id" jsonschema:"the webhook subscription ID"`
	skycloak.UpdateWebhookSubscriptionRequest
}

func updateWebhookSubscriptionHandler(api API) mcp.ToolHandlerFor[UpdateWebhookSubscriptionInput, skycloak.WebhookSubscription] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateWebhookSubscriptionInput) (*mcp.CallToolResult, skycloak.WebhookSubscription, error) {
		if in.WebhookID == "" {
			return errResult("webhook_id is required"), skycloak.WebhookSubscription{}, nil
		}
		in.Source = enumWebhookSource.canonicalPtr(in.Source)
		h, err := api.UpdateWebhookSubscription(ctx, in.WebhookID, in.UpdateWebhookSubscriptionRequest)
		if err != nil {
			return toolError(err), skycloak.WebhookSubscription{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated " + webhookText(h)}}}, *h, nil
	}
}

// WebhookConfirmInput confirms a webhook subscription deletion.
type WebhookConfirmInput struct {
	WebhookID string `json:"webhook_id" jsonschema:"the webhook subscription ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteWebhookSubscriptionHandler(api API) mcp.ToolHandlerFor[WebhookConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in WebhookConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.WebhookID == "" {
			return errResult("webhook_id is required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete webhook subscription %s: set confirm=true.", in.WebhookID)), struct{}{}, nil
		}
		if err := api.DeleteWebhookSubscription(ctx, in.WebhookID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Deleted webhook subscription %s.", in.WebhookID)}}}, struct{}{}, nil
	}
}

// TestWebhookSubscriptionInput is the input for skycloak_test_webhook_subscription.
type TestWebhookSubscriptionInput struct {
	WebhookID string `json:"webhook_id" jsonschema:"the webhook subscription ID"`
	EventType string `json:"event_type,omitempty" jsonschema:"optional event type to test"`
}

func testWebhookSubscriptionHandler(api API) mcp.ToolHandlerFor[TestWebhookSubscriptionInput, skycloak.WebhookTestResult] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in TestWebhookSubscriptionInput) (*mcp.CallToolResult, skycloak.WebhookTestResult, error) {
		if in.WebhookID == "" {
			return errResult("webhook_id is required"), skycloak.WebhookTestResult{}, nil
		}
		out, err := api.TestWebhookSubscription(ctx, in.WebhookID, skycloak.TestWebhookSubscriptionRequest{EventType: in.EventType})
		if err != nil {
			return toolError(err), skycloak.WebhookTestResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Webhook test success=%t delivery_id=%s", out.Success, out.DeliveryID)}}}, *out, nil
	}
}

func webhookText(h *skycloak.WebhookSubscription) string {
	return fmt.Sprintf("webhook subscription %q (%s) source=%s enabled=%t events=%d", h.Name, h.ID, h.Source, h.Enabled, len(h.EventTypes))
}
