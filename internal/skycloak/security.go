package skycloak

import (
	"context"

	"github.com/sky-cloak/skycloak-mcp/internal/apiclient"
)

// ClusterSecurity is the edge-security configuration for a cluster (IP access
// control, rate limiting, WAF, geo-blocking, bot management). The CAPTCHA
// sub-config is not surfaced here and is preserved untouched on update.
type ClusterSecurity struct {
	IPAccessControl *IPAccessControl `json:"ip_access_control,omitempty"`
	RateLimiting    *RateLimiting    `json:"rate_limiting,omitempty"`
	WAF             *WAF             `json:"waf,omitempty"`
	GeoBlocking     *GeoBlocking     `json:"geo_blocking,omitempty"`
	BotManagement   *BotManagement   `json:"bot_management,omitempty"`
}

// IPPathRule restricts a URL path to a set of IPs/CIDRs.
type IPPathRule struct {
	Path         string   `json:"path"`
	Description  string   `json:"description,omitempty"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

// IPAccessControl holds per-path IP allow rules.
type IPAccessControl struct {
	PathRules []IPPathRule `json:"path_rules"`
}

// EndpointLimit caps requests-per-minute on a path.
type EndpointLimit struct {
	Path string `json:"path"`
	RPM  int64  `json:"rpm"`
}

// RateLimiting configures request-rate ceilings.
type RateLimiting struct {
	Enabled        bool            `json:"enabled"`
	GlobalRPM      int64           `json:"global_rpm,omitempty"`
	PerIPRPM       int64           `json:"per_ip_rpm,omitempty"`
	EndpointLimits []EndpointLimit `json:"endpoint_limits,omitempty"`
}

// WAFCategories toggles OWASP CRS rule categories.
type WAFCategories struct {
	CrossSiteScripting  bool `json:"cross_site_scripting"`
	DataLeakage         bool `json:"data_leakage"`
	JavaAttacks         bool `json:"java_attacks"`
	LocalFileInclusion  bool `json:"local_file_inclusion"`
	PhpInjection        bool `json:"php_injection"`
	ProtocolAttacks     bool `json:"protocol_attacks"`
	ProtocolEnforcement bool `json:"protocol_enforcement"`
	RemoteCodeExecution bool `json:"remote_code_execution"`
	RemoteFileInclusion bool `json:"remote_file_inclusion"`
	SessionFixation     bool `json:"session_fixation"`
	SQLInjection        bool `json:"sql_injection"`
	WebshellDetection   bool `json:"webshell_detection"`
}

// WAF configures the web application firewall.
type WAF struct {
	Enabled       bool           `json:"enabled"`
	Mode          string         `json:"mode"`
	Preset        string         `json:"preset"`
	ParanoiaLevel int64          `json:"paranoia_level"`
	Categories    *WAFCategories `json:"categories,omitempty"`
}

// GeoBlocking restricts access by country.
type GeoBlocking struct {
	Enabled   bool     `json:"enabled"`
	Mode      string   `json:"mode"`
	Countries []string `json:"countries"`
}

// BotManagement configures bot detection and challenges.
type BotManagement struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	ChallengeMode string `json:"challenge_mode"`
}

func derefIntStar(p *int) int64 {
	if p == nil {
		return 0
	}
	return int64(*p)
}

func derefSlice(p *[]string) []string {
	if p == nil {
		return nil
	}
	return *p
}

func securityFromAPI(c *apiclient.ClusterSecurityConfig) *ClusterSecurity {
	out := &ClusterSecurity{}
	if c.IpAccessControl != nil {
		ipc := &IPAccessControl{}
		for _, r := range c.IpAccessControl.PathRules {
			ipc.PathRules = append(ipc.PathRules, IPPathRule{Path: r.Path, Description: strDeref(r.Description), AllowedIPs: derefSlice(r.AllowedIps), AllowedCIDRs: derefSlice(r.AllowedCidrs)})
		}
		out.IPAccessControl = ipc
	}
	if c.RateLimiting != nil {
		rl := &RateLimiting{Enabled: c.RateLimiting.Enabled, GlobalRPM: derefIntStar(c.RateLimiting.GlobalRpm), PerIPRPM: derefIntStar(c.RateLimiting.PerIpRpm)}
		if c.RateLimiting.EndpointLimits != nil {
			for _, e := range *c.RateLimiting.EndpointLimits {
				rl.EndpointLimits = append(rl.EndpointLimits, EndpointLimit{Path: e.Path, RPM: int64(e.Rpm)})
			}
		}
		out.RateLimiting = rl
	}
	if c.Waf != nil {
		w := &WAF{Enabled: c.Waf.Enabled, Mode: string(c.Waf.Mode), Preset: string(c.Waf.Preset), ParanoiaLevel: int64(c.Waf.ParanoiaLevel)}
		if cat := c.Waf.EnabledCategories; cat != nil {
			w.Categories = &WAFCategories{
				CrossSiteScripting: cat.CrossSiteScripting, DataLeakage: cat.DataLeakage, JavaAttacks: cat.JavaAttacks,
				LocalFileInclusion: cat.LocalFileInclusion, PhpInjection: cat.PhpInjection, ProtocolAttacks: cat.ProtocolAttacks,
				ProtocolEnforcement: cat.ProtocolEnforcement, RemoteCodeExecution: cat.RemoteCodeExecution, RemoteFileInclusion: cat.RemoteFileInclusion,
				SessionFixation: cat.SessionFixation, SQLInjection: cat.SqlInjection, WebshellDetection: cat.WebshellDetection,
			}
		}
		out.WAF = w
	}
	if c.GeoBlocking != nil {
		out.GeoBlocking = &GeoBlocking{Enabled: c.GeoBlocking.Enabled, Mode: string(c.GeoBlocking.Mode), Countries: c.GeoBlocking.Countries}
	}
	if c.BotManagement != nil {
		out.BotManagement = &BotManagement{Enabled: c.BotManagement.Enabled, Mode: string(c.BotManagement.Mode), ChallengeMode: string(c.BotManagement.ChallengeMode)}
	}
	return out
}

func sptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *ClusterSecurity) applyToAPI(c *apiclient.ClusterSecurityConfig) {
	if s.IPAccessControl != nil {
		rules := make([]apiclient.IPPathRule, 0, len(s.IPAccessControl.PathRules))
		for _, r := range s.IPAccessControl.PathRules {
			rule := apiclient.IPPathRule{Path: r.Path, Description: sptr(r.Description)}
			if len(r.AllowedIPs) > 0 {
				ips := r.AllowedIPs
				rule.AllowedIps = &ips
			}
			if len(r.AllowedCIDRs) > 0 {
				cidrs := r.AllowedCIDRs
				rule.AllowedCidrs = &cidrs
			}
			rules = append(rules, rule)
		}
		c.IpAccessControl = &apiclient.IPAccessControlConfig{PathRules: rules}
	}
	if s.RateLimiting != nil {
		rl := &apiclient.RateLimitingConfig{Enabled: s.RateLimiting.Enabled}
		if s.RateLimiting.GlobalRPM > 0 {
			g := int(s.RateLimiting.GlobalRPM)
			rl.GlobalRpm = &g
		}
		if s.RateLimiting.PerIPRPM > 0 {
			p := int(s.RateLimiting.PerIPRPM)
			rl.PerIpRpm = &p
		}
		if len(s.RateLimiting.EndpointLimits) > 0 {
			lims := make([]apiclient.EndpointRateLimit, 0, len(s.RateLimiting.EndpointLimits))
			for _, e := range s.RateLimiting.EndpointLimits {
				lims = append(lims, apiclient.EndpointRateLimit{Path: e.Path, Rpm: int(e.RPM)})
			}
			rl.EndpointLimits = &lims
		}
		c.RateLimiting = rl
	}
	if s.WAF != nil {
		w := &apiclient.WAFConfig{Enabled: s.WAF.Enabled, Mode: apiclient.SecurityMode(s.WAF.Mode), Preset: apiclient.WAFPreset(s.WAF.Preset), ParanoiaLevel: int(s.WAF.ParanoiaLevel)}
		if cat := s.WAF.Categories; cat != nil {
			w.EnabledCategories = &apiclient.WAFCategories{
				CrossSiteScripting: cat.CrossSiteScripting, DataLeakage: cat.DataLeakage, JavaAttacks: cat.JavaAttacks,
				LocalFileInclusion: cat.LocalFileInclusion, PhpInjection: cat.PhpInjection, ProtocolAttacks: cat.ProtocolAttacks,
				ProtocolEnforcement: cat.ProtocolEnforcement, RemoteCodeExecution: cat.RemoteCodeExecution, RemoteFileInclusion: cat.RemoteFileInclusion,
				SessionFixation: cat.SessionFixation, SqlInjection: cat.SQLInjection, WebshellDetection: cat.WebshellDetection,
			}
		}
		c.Waf = w
	}
	if s.GeoBlocking != nil {
		c.GeoBlocking = &apiclient.GeoBlockingConfig{Enabled: s.GeoBlocking.Enabled, Mode: apiclient.GeoBlockingMode(s.GeoBlocking.Mode), Countries: s.GeoBlocking.Countries}
	}
	if s.BotManagement != nil {
		c.BotManagement = &apiclient.BotManagementConfig{Enabled: s.BotManagement.Enabled, Mode: apiclient.SecurityMode(s.BotManagement.Mode), ChallengeMode: apiclient.BotChallengeMode(s.BotManagement.ChallengeMode)}
	}
}

// GetClusterSecurity returns a cluster's edge-security configuration.
func (c *Client) GetClusterSecurity(ctx context.Context, clusterID string) (*ClusterSecurity, error) {
	resp, err := c.gen.GetClusterSecurityWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return securityFromAPI(resp.JSON200), nil
}

// UpdateClusterSecurity overlays the managed sections onto the cluster's current
// config (preserving CAPTCHA) and saves it.
func (c *Client) UpdateClusterSecurity(ctx context.Context, clusterID string, sec *ClusterSecurity) (*ClusterSecurity, error) {
	cur, err := c.gen.GetClusterSecurityWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	// The read is what preserves the sections this call does not manage, CAPTCHA
	// among them. A non-200 here (a 403 from a key without clusters:security:read
	// is the likely one) used to fall through to an empty body, so the update
	// silently wiped everything the caller had not supplied. Fail instead.
	if cur.JSON200 == nil {
		return nil, statusError(cur.HTTPResponse, cur.Body)
	}
	body := *cur.JSON200
	body.IpAccessControl, body.RateLimiting, body.Waf, body.GeoBlocking, body.BotManagement = nil, nil, nil, nil, nil
	sec.applyToAPI(&body)
	resp, err := c.gen.UpdateClusterSecurityWithResponse(ctx, cid(clusterID), nil, apiclient.UpdateClusterSecurityJSONRequestBody(body))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return securityFromAPI(resp.JSON200), nil
}
