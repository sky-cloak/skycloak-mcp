package skycloak

import (
	"context"

	"github.com/oapi-codegen/nullable"

	"github.com/sky-cloak/skycloak-mcp/internal/apiclient"
)

// CAPTCHADomain is a hostname registered for CAPTCHA protection.
type CAPTCHADomain struct {
	Hostname  string `json:"hostname"`
	CreatedAt string `json:"created_at"`
}

// CAPTCHADomainsInfo lists CAPTCHA domains and the cluster limit.
type CAPTCHADomainsInfo struct {
	Domains    []CAPTCHADomain `json:"domains"`
	MaxAllowed int             `json:"max_allowed"`
}

func captchaDomainFromAPI(d apiclient.CAPTCHADomain) CAPTCHADomain {
	return CAPTCHADomain{Hostname: d.Hostname, CreatedAt: fmtTime(d.CreatedAt)}
}

// ListClusterCAPTCHADomains returns CAPTCHA-protected hostnames for a cluster.
func (c *Client) ListClusterCAPTCHADomains(ctx context.Context, clusterID string) (*CAPTCHADomainsInfo, error) {
	resp, err := c.gen.ListClusterCAPTCHADomainsWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := &CAPTCHADomainsInfo{MaxAllowed: resp.JSON200.MaxAllowed}
	for _, d := range resp.JSON200.Domains {
		out.Domains = append(out.Domains, captchaDomainFromAPI(d))
	}
	return out, nil
}

// AddClusterCAPTCHADomain registers a hostname for CAPTCHA protection.
func (c *Client) AddClusterCAPTCHADomain(ctx context.Context, clusterID, hostname string) (*CAPTCHADomain, error) {
	resp, err := c.gen.AddClusterCAPTCHADomainWithResponse(ctx, cid(clusterID), nil, apiclient.AddClusterCAPTCHADomainJSONRequestBody{Hostname: hostname})
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := captchaDomainFromAPI(*resp.JSON201)
	return &out, nil
}

// RemoveClusterCAPTCHADomain removes a hostname from CAPTCHA protection.
func (c *Client) RemoveClusterCAPTCHADomain(ctx context.Context, clusterID, hostname string) error {
	resp, err := c.gen.RemoveClusterCAPTCHADomainWithResponse(ctx, cid(clusterID), hostname, nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// SIEMBatchConfig controls SIEM forwarding batch size and interval.
type SIEMBatchConfig struct {
	MaxEvents          *int `json:"max_events,omitempty"`
	MaxIntervalSeconds *int `json:"max_interval_seconds,omitempty"`
}

// SIEMSourceConfig selects workspace data forwarded to SIEM.
type SIEMSourceConfig struct {
	Type               string   `json:"type" jsonschema:"data to forward: keycloak_events, application_logs, security_logs, or skycloak_audit (case-insensitive)"`
	ClusterIDs         []string `json:"cluster_ids,omitempty"`
	Realms             []string `json:"realms,omitempty"`
	KeycloakEventTypes []string `json:"keycloak_event_types,omitempty"`
}

// SIEMSyslogConfig configures a syslog SIEM destination.
type SIEMSyslogConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol" jsonschema:"transport: udp, tcp, or tls (case-insensitive)"`
	Format   string `json:"format" jsonschema:"message format: cef, leef, rfc5424, or json (case-insensitive)"`
}

// SIEMS3Config configures an S3 SIEM destination request.
type SIEMS3Config struct {
	AuthType        string `json:"auth_type" jsonschema:"authentication: access_key, iam_role, assume_role, or irsa (case-insensitive)"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	Prefix          string `json:"prefix,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	ExternalID      string `json:"external_id,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
}

// SIEMHTTPConfig configures an HTTP SIEM destination request.
type SIEMHTTPConfig struct {
	URL         string            `json:"url"`
	AuthType    string            `json:"auth_type" jsonschema:"authentication: none, bearer, or basic (case-insensitive)"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	BearerToken string            `json:"bearer_token,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// SIEMS3DestinationConfig describes a saved S3 SIEM destination.
type SIEMS3DestinationConfig struct {
	AuthType           string `json:"auth_type"`
	Bucket             string `json:"bucket"`
	Region             string `json:"region"`
	Prefix             string `json:"prefix,omitempty"`
	RoleARN            string `json:"role_arn,omitempty"`
	ExternalID         string `json:"external_id,omitempty"`
	HasAccessKeySecret bool   `json:"has_access_key_secret"`
}

// SIEMHTTPDestinationConfig describes a saved HTTP SIEM destination.
type SIEMHTTPDestinationConfig struct {
	URL                string   `json:"url"`
	AuthType           string   `json:"auth_type"`
	HasAuthCredentials bool     `json:"has_auth_credentials"`
	HeaderNames        []string `json:"header_names"`
}

// SIEMDestination is a saved workspace SIEM forwarding destination.
type SIEMDestination struct {
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Type            string                     `json:"type"`
	Enabled         bool                       `json:"enabled"`
	Source          SIEMSourceConfig           `json:"source"`
	Batch           SIEMBatchConfig            `json:"batch"`
	Syslog          *SIEMSyslogConfig          `json:"syslog,omitempty"`
	S3              *SIEMS3DestinationConfig   `json:"s3,omitempty"`
	HTTP            *SIEMHTTPDestinationConfig `json:"http,omitempty"`
	HealthStatus    string                     `json:"health_status"`
	LastError       string                     `json:"last_error,omitempty"`
	LastSentAt      string                     `json:"last_sent_at,omitempty"`
	FailureCount    int                        `json:"failure_count"`
	TotalEventsSent int64                      `json:"total_events_sent"`
	TotalLogsSent   int64                      `json:"total_logs_sent"`
	TotalBytesSent  int64                      `json:"total_bytes_sent"`
	CreatedAt       string                     `json:"created_at"`
	UpdatedAt       string                     `json:"updated_at"`
}

// CreateSIEMDestinationRequest creates a SIEM destination.
type CreateSIEMDestinationRequest struct {
	Name   string            `json:"name"`
	Type   string            `json:"type" jsonschema:"destination transport: syslog, s3, or http (case-insensitive)"`
	Source SIEMSourceConfig  `json:"source"`
	Batch  *SIEMBatchConfig  `json:"batch,omitempty"`
	Syslog *SIEMSyslogConfig `json:"syslog,omitempty"`
	S3     *SIEMS3Config     `json:"s3,omitempty"`
	HTTP   *SIEMHTTPConfig   `json:"http,omitempty"`
}

// UpdateSIEMDestinationRequest updates a SIEM destination.
type UpdateSIEMDestinationRequest struct {
	Name    *string           `json:"name,omitempty"`
	Source  *SIEMSourceConfig `json:"source,omitempty"`
	Batch   *SIEMBatchConfig  `json:"batch,omitempty"`
	Syslog  *SIEMSyslogConfig `json:"syslog,omitempty"`
	S3      *SIEMS3Config     `json:"s3,omitempty"`
	HTTP    *SIEMHTTPConfig   `json:"http,omitempty"`
	Enabled *bool             `json:"enabled,omitempty"`
}

// SIEMDestinationTestResult is the result of testing a SIEM destination.
type SIEMDestinationTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

func sourceToAPI(s SIEMSourceConfig) apiclient.SIEMSourceConfig {
	out := apiclient.SIEMSourceConfig{Type: apiclient.SIEMSourceType(s.Type)}
	if len(s.ClusterIDs) > 0 {
		ids := make([]apiclient.ClusterId, 0, len(s.ClusterIDs))
		for _, id := range s.ClusterIDs {
			ids = append(ids, cid(id))
		}
		out.ClusterIds = &ids
	}
	if len(s.Realms) > 0 {
		realms := make([]apiclient.RealmName, 0, len(s.Realms))
		for _, r := range s.Realms {
			realms = append(realms, apiclient.RealmName(r))
		}
		out.Realms = &realms
	}
	if len(s.KeycloakEventTypes) > 0 {
		out.KeycloakEventTypes = &s.KeycloakEventTypes
	}
	return out
}

func sourceFromAPI(s apiclient.SIEMSourceConfig) SIEMSourceConfig {
	out := SIEMSourceConfig{Type: string(s.Type)}
	if s.ClusterIds != nil {
		for _, id := range *s.ClusterIds {
			out.ClusterIDs = append(out.ClusterIDs, id.String())
		}
	}
	if s.Realms != nil {
		for _, r := range *s.Realms {
			out.Realms = append(out.Realms, string(r))
		}
	}
	if s.KeycloakEventTypes != nil {
		out.KeycloakEventTypes = *s.KeycloakEventTypes
	}
	return out
}

func batchToAPI(b *SIEMBatchConfig) *apiclient.SIEMBatchConfig {
	if b == nil {
		return nil
	}
	return &apiclient.SIEMBatchConfig{MaxEvents: b.MaxEvents, MaxIntervalSeconds: b.MaxIntervalSeconds}
}

func batchFromAPI(b apiclient.SIEMBatchConfig) SIEMBatchConfig {
	return SIEMBatchConfig{MaxEvents: b.MaxEvents, MaxIntervalSeconds: b.MaxIntervalSeconds}
}

func syslogToAPI(s *SIEMSyslogConfig) *apiclient.SIEMSyslogConfig {
	if s == nil {
		return nil
	}
	return &apiclient.SIEMSyslogConfig{Host: s.Host, Port: s.Port, Protocol: apiclient.SyslogProtocol(s.Protocol), Format: apiclient.SyslogFormat(s.Format)}
}

func syslogFromAPI(s *apiclient.SIEMSyslogConfig) *SIEMSyslogConfig {
	if s == nil {
		return nil
	}
	return &SIEMSyslogConfig{Host: s.Host, Port: s.Port, Protocol: string(s.Protocol), Format: string(s.Format)}
}

func s3ToAPI(s *SIEMS3Config) *apiclient.SIEMS3Config {
	if s == nil {
		return nil
	}
	return &apiclient.SIEMS3Config{AuthType: apiclient.S3AuthType(s.AuthType), Bucket: s.Bucket, Region: s.Region, Prefix: sptr(s.Prefix), RoleArn: sptr(s.RoleARN), ExternalId: sptr(s.ExternalID), AccessKeyId: sptr(s.AccessKeyID), SecretAccessKey: sptr(s.SecretAccessKey)}
}

func s3FromAPI(s *apiclient.SIEMS3DestinationConfig) *SIEMS3DestinationConfig {
	if s == nil {
		return nil
	}
	return &SIEMS3DestinationConfig{AuthType: string(s.AuthType), Bucket: s.Bucket, Region: s.Region, Prefix: strDeref(s.Prefix), RoleARN: strDeref(s.RoleArn), ExternalID: strDeref(s.ExternalId), HasAccessKeySecret: s.HasAccessKeySecret}
}

func httpToAPI(h *SIEMHTTPConfig) *apiclient.SIEMHTTPConfig {
	if h == nil {
		return nil
	}
	out := &apiclient.SIEMHTTPConfig{Url: h.URL, AuthType: apiclient.HTTPAuthType(h.AuthType), Username: sptr(h.Username), Password: sptr(h.Password), BearerToken: sptr(h.BearerToken)}
	if len(h.Headers) > 0 {
		out.Headers = &h.Headers
	}
	return out
}

func httpFromAPI(h *apiclient.SIEMHTTPDestinationConfig) *SIEMHTTPDestinationConfig {
	if h == nil {
		return nil
	}
	return &SIEMHTTPDestinationConfig{URL: h.Url, AuthType: string(h.AuthType), HasAuthCredentials: h.HasAuthCredentials, HeaderNames: h.HeaderNames}
}

func siemDestinationFromAPI(d *apiclient.SIEMDestination) *SIEMDestination {
	out := &SIEMDestination{
		ID: d.Id.String(), Name: string(d.Name), Type: string(d.Type), Enabled: d.Enabled,
		Source: sourceFromAPI(d.Source), Batch: batchFromAPI(d.Batch), Syslog: syslogFromAPI(d.Syslog), S3: s3FromAPI(d.S3), HTTP: httpFromAPI(d.Http),
		HealthStatus: string(d.HealthStatus), LastError: strDeref(d.LastError), FailureCount: d.FailureCount,
		TotalEventsSent: d.TotalEventsSent, TotalLogsSent: d.TotalLogsSent, TotalBytesSent: d.TotalBytesSent,
		CreatedAt: fmtTime(d.CreatedAt), UpdatedAt: fmtTime(d.UpdatedAt),
	}
	if d.LastSentAt != nil {
		out.LastSentAt = fmtTime(*d.LastSentAt)
	}
	return out
}

// ListSIEMDestinations returns SIEM destinations configured for the workspace.
func (c *Client) ListSIEMDestinations(ctx context.Context) ([]SIEMDestination, error) {
	resp, err := c.gen.ListSIEMDestinationsWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]SIEMDestination, 0, len(*resp.JSON200))
	for _, d := range *resp.JSON200 {
		out = append(out, *siemDestinationFromAPI(&d))
	}
	return out, nil
}

// CreateSIEMDestination creates a workspace SIEM destination.
func (c *Client) CreateSIEMDestination(ctx context.Context, req CreateSIEMDestinationRequest) (*SIEMDestination, error) {
	body := apiclient.CreateSIEMDestinationJSONRequestBody{Name: apiclient.SIEMDestinationName(req.Name), Type: apiclient.SIEMDestinationType(req.Type), Source: sourceToAPI(req.Source), Batch: batchToAPI(req.Batch), Syslog: syslogToAPI(req.Syslog), S3: s3ToAPI(req.S3), Http: httpToAPI(req.HTTP)}
	resp, err := c.gen.CreateSIEMDestinationWithResponse(ctx, nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return siemDestinationFromAPI(resp.JSON201), nil
}

// GetSIEMDestination returns a SIEM destination by ID.
func (c *Client) GetSIEMDestination(ctx context.Context, destinationID string) (*SIEMDestination, error) {
	resp, err := c.gen.GetSIEMDestinationWithResponse(ctx, uid(destinationID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return siemDestinationFromAPI(resp.JSON200), nil
}

// UpdateSIEMDestination updates a SIEM destination by ID.
func (c *Client) UpdateSIEMDestination(ctx context.Context, destinationID string, req UpdateSIEMDestinationRequest) (*SIEMDestination, error) {
	body := apiclient.UpdateSIEMDestinationJSONRequestBody{Batch: batchToAPI(req.Batch), Syslog: syslogToAPI(req.Syslog), S3: s3ToAPI(req.S3), Http: httpToAPI(req.HTTP), Enabled: req.Enabled}
	if req.Name != nil {
		name := apiclient.SIEMDestinationName(*req.Name)
		body.Name = &name
	}
	if req.Source != nil {
		source := sourceToAPI(*req.Source)
		body.Source = &source
	}
	resp, err := c.gen.UpdateSIEMDestinationWithResponse(ctx, uid(destinationID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return siemDestinationFromAPI(resp.JSON200), nil
}

// DeleteSIEMDestination deletes a SIEM destination by ID.
func (c *Client) DeleteSIEMDestination(ctx context.Context, destinationID string) error {
	resp, err := c.gen.DeleteSIEMDestinationWithResponse(ctx, uid(destinationID), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// TestSIEMDestination sends a test event to a SIEM destination.
func (c *Client) TestSIEMDestination(ctx context.Context, destinationID string) (*SIEMDestinationTestResult, error) {
	resp, err := c.gen.TestSIEMDestinationWithResponse(ctx, uid(destinationID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return &SIEMDestinationTestResult{Success: resp.JSON200.Success, Message: strDeref(resp.JSON200.Message)}, nil
}

// WebhookEventType describes an event type available for subscriptions.
type WebhookEventType struct {
	Type          string                 `json:"type"`
	Category      string                 `json:"category"`
	Description   string                 `json:"description"`
	Deprecated    bool                   `json:"deprecated"`
	SamplePayload map[string]interface{} `json:"sample_payload,omitempty"`
}

// ListWebhookSubscriptionsFilter filters webhook subscriptions.
type ListWebhookSubscriptionsFilter struct {
	Source    string `json:"source,omitempty" jsonschema:"optional source filter: keycloak or platform (case-insensitive)"`
	ClusterID string `json:"cluster_id,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
}

// WebhookSubscription is a saved webhook subscription.
type WebhookSubscription struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	URL                    string   `json:"url"`
	Source                 string   `json:"source"`
	Enabled                bool     `json:"enabled"`
	EventTypes             []string `json:"event_types"`
	ClusterID              string   `json:"cluster_id,omitempty"`
	RealmID                string   `json:"realm_id,omitempty"`
	HasSigningSecret       bool     `json:"has_signing_secret"`
	HasAuthorizationHeader bool     `json:"has_authorization_header"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
}

// CreateWebhookSubscriptionRequest creates a webhook subscription.
type CreateWebhookSubscriptionRequest struct {
	Name                string   `json:"name"`
	URL                 string   `json:"url"`
	Source              string   `json:"source" jsonschema:"event source: keycloak or platform (case-insensitive)"`
	EventTypes          []string `json:"event_types"`
	SigningSecret       string   `json:"signing_secret"`
	AuthorizationHeader string   `json:"authorization_header,omitempty"`
	ClusterID           string   `json:"cluster_id,omitempty"`
	RealmID             string   `json:"realm_id,omitempty"`
	Enabled             *bool    `json:"enabled,omitempty"`
}

// UpdateWebhookSubscriptionRequest updates a webhook subscription.
type UpdateWebhookSubscriptionRequest struct {
	Name                     *string   `json:"name,omitempty"`
	URL                      *string   `json:"url,omitempty"`
	Source                   *string   `json:"source,omitempty" jsonschema:"new event source: keycloak or platform (case-insensitive)"`
	EventTypes               *[]string `json:"event_types,omitempty"`
	SigningSecret            *string   `json:"signing_secret,omitempty"`
	AuthorizationHeader      *string   `json:"authorization_header,omitempty"`
	ClearAuthorizationHeader bool      `json:"clear_authorization_header,omitempty"`
	ClusterID                *string   `json:"cluster_id,omitempty"`
	ClearClusterID           bool      `json:"clear_cluster_id,omitempty"`
	RealmID                  *string   `json:"realm_id,omitempty"`
	ClearRealmID             bool      `json:"clear_realm_id,omitempty"`
	Enabled                  *bool     `json:"enabled,omitempty"`
}

// TestWebhookSubscriptionRequest selects the webhook event type to test.
type TestWebhookSubscriptionRequest struct {
	EventType string `json:"event_type,omitempty"`
}

// WebhookTestResult is the result of testing a webhook subscription.
type WebhookTestResult struct {
	Success      bool   `json:"success"`
	DeliveryID   string `json:"delivery_id"`
	ResponseCode int    `json:"response_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	ResponseBody string `json:"response_body,omitempty"`
	DurationMS   int64  `json:"duration_ms"`
	AttemptedAt  string `json:"attempted_at"`
}

// ListWebhookEventTypes returns webhook event types, optionally filtered by source.
func (c *Client) ListWebhookEventTypes(ctx context.Context, source string) ([]WebhookEventType, error) {
	var params *apiclient.ListWebhookEventTypesParams
	if source != "" {
		src := apiclient.WebhookSource(source)
		params = &apiclient.ListWebhookEventTypesParams{Source: &src}
	}
	resp, err := c.gen.ListWebhookEventTypesWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]WebhookEventType, 0, len(*resp.JSON200))
	for _, e := range *resp.JSON200 {
		event := WebhookEventType{Type: e.Type, Category: string(e.Category), Description: e.Description, Deprecated: e.Deprecated}
		if e.SamplePayload.IsSpecified() && !e.SamplePayload.IsNull() {
			if v, err := e.SamplePayload.Get(); err == nil {
				event.SamplePayload = v
			}
		}
		out = append(out, event)
	}
	return out, nil
}

// ListWebhookSubscriptions returns webhook subscriptions matching the filter.
func (c *Client) ListWebhookSubscriptions(ctx context.Context, filter ListWebhookSubscriptionsFilter) ([]WebhookSubscription, error) {
	params := &apiclient.ListWebhookSubscriptionsParams{Enabled: filter.Enabled}
	if filter.Source != "" {
		src := apiclient.WebhookSource(filter.Source)
		params.Source = &src
	}
	if filter.ClusterID != "" {
		id := cid(filter.ClusterID)
		params.ClusterId = &id
	}
	resp, err := c.gen.ListWebhookSubscriptionsWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]WebhookSubscription, 0, len(*resp.JSON200))
	for _, w := range *resp.JSON200 {
		out = append(out, *webhookSubscriptionFromAPI(&w))
	}
	return out, nil
}

func webhookSubscriptionFromAPI(w *apiclient.WebhookSubscription) *WebhookSubscription {
	out := &WebhookSubscription{
		ID: w.Id.String(), Name: string(w.Name), URL: w.Url, Source: string(w.Source), Enabled: w.Enabled, EventTypes: w.EventTypes,
		HasSigningSecret: w.HasSigningSecret, HasAuthorizationHeader: w.HasAuthorizationHeader, CreatedAt: fmtTime(w.CreatedAt), UpdatedAt: fmtTime(w.UpdatedAt),
	}
	if w.ClusterId != nil {
		out.ClusterID = w.ClusterId.String()
	}
	out.RealmID = strDeref(w.RealmId)
	return out
}

// CreateWebhookSubscription creates a webhook subscription.
func (c *Client) CreateWebhookSubscription(ctx context.Context, req CreateWebhookSubscriptionRequest) (*WebhookSubscription, error) {
	body := apiclient.CreateWebhookSubscriptionJSONRequestBody{
		Name: apiclient.WebhookSubscriptionName(req.Name), Url: apiclient.WebhookUrl(req.URL), Source: apiclient.WebhookSource(req.Source),
		EventTypes: req.EventTypes, SigningSecret: apiclient.WebhookSigningSecret(req.SigningSecret), AuthorizationHeader: sptr(req.AuthorizationHeader),
		ClusterId: nil, RealmId: nil, Enabled: req.Enabled,
	}
	if req.ClusterID != "" {
		id := cid(req.ClusterID)
		body.ClusterId = &id
	}
	if req.RealmID != "" {
		id := uid(req.RealmID)
		body.RealmId = &id
	}
	resp, err := c.gen.CreateWebhookSubscriptionWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return webhookSubscriptionFromAPI(resp.JSON201), nil
}

// GetWebhookSubscription returns a webhook subscription by ID.
func (c *Client) GetWebhookSubscription(ctx context.Context, webhookID string) (*WebhookSubscription, error) {
	resp, err := c.gen.GetWebhookSubscriptionWithResponse(ctx, uid(webhookID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return webhookSubscriptionFromAPI(resp.JSON200), nil
}

// UpdateWebhookSubscription updates a webhook subscription by ID.
func (c *Client) UpdateWebhookSubscription(ctx context.Context, webhookID string, req UpdateWebhookSubscriptionRequest) (*WebhookSubscription, error) {
	body := apiclient.UpdateWebhookSubscriptionJSONRequestBody{Enabled: req.Enabled, EventTypes: req.EventTypes}
	if req.Name != nil {
		name := apiclient.WebhookSubscriptionName(*req.Name)
		body.Name = &name
	}
	if req.URL != nil {
		url := apiclient.WebhookUrl(*req.URL)
		body.Url = &url
	}
	if req.Source != nil {
		source := apiclient.WebhookSource(*req.Source)
		body.Source = &source
	}
	if req.SigningSecret != nil {
		secret := apiclient.WebhookSigningSecret(*req.SigningSecret)
		body.SigningSecret = &secret
	}
	if req.AuthorizationHeader != nil {
		body.AuthorizationHeader = nullable.NewNullableWithValue(apiclient.WebhookAuthorizationHeader(*req.AuthorizationHeader))
	} else if req.ClearAuthorizationHeader {
		body.AuthorizationHeader = nullable.NewNullNullable[apiclient.WebhookAuthorizationHeader]()
	}
	if req.ClusterID != nil {
		body.ClusterId = nullable.NewNullableWithValue(cid(*req.ClusterID))
	} else if req.ClearClusterID {
		body.ClusterId = nullable.NewNullNullable[apiclient.ClusterId]()
	}
	if req.RealmID != nil {
		body.RealmId = nullable.NewNullableWithValue(uid(*req.RealmID))
	} else if req.ClearRealmID {
		body.RealmId = nullable.NewNullNullable[apiclient.RealmId]()
	}
	resp, err := c.gen.UpdateWebhookSubscriptionWithResponse(ctx, uid(webhookID), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return webhookSubscriptionFromAPI(resp.JSON200), nil
}

// DeleteWebhookSubscription deletes a webhook subscription by ID.
func (c *Client) DeleteWebhookSubscription(ctx context.Context, webhookID string) error {
	resp, err := c.gen.DeleteWebhookSubscriptionWithResponse(ctx, uid(webhookID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// TestWebhookSubscription sends a test event to a webhook subscription.
func (c *Client) TestWebhookSubscription(ctx context.Context, webhookID string, req TestWebhookSubscriptionRequest) (*WebhookTestResult, error) {
	body := apiclient.TestWebhookSubscriptionJSONRequestBody{EventType: req.EventType}
	resp, err := c.gen.TestWebhookSubscriptionWithResponse(ctx, uid(webhookID), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := &WebhookTestResult{Success: resp.JSON200.Success, DeliveryID: resp.JSON200.DeliveryId, DurationMS: resp.JSON200.DurationMs, AttemptedAt: fmtTime(resp.JSON200.AttemptedAt), ErrorMessage: strDeref(resp.JSON200.ErrorMessage), ResponseBody: strDeref(resp.JSON200.ResponseBody)}
	if resp.JSON200.ResponseCode != nil {
		out.ResponseCode = *resp.JSON200.ResponseCode
	}
	return out, nil
}
