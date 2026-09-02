package tools

import (
	"strconv"
	"strings"
	"testing"
)

// The canned prompts are instructions a model follows literally, so a stale one
// is worse than stale docs: it steers every caller into a call that fails or
// silently answers wrong. These pin them to what the tools actually do now.

// allPromptText renders every prompt with representative arguments.
func allPromptText() map[string]string {
	args := map[string]string{
		"realm": "alfred", "cluster_id": "c1", "cluster_name": "prod",
		"domain": "auth.example.com", "window": "the last 7 days",
	}
	return map[string]string{
		"triage_failed_logins":      triageFailedLoginsText(args),
		"review_admin_changes":      reviewAdminChangesText(args),
		"review_identity_providers": reviewIdentityProvidersText(args),
	}
}

// search never matched the event type. A prompt telling callers to filter that
// way reproduces the original bug: zero results for a realm that has failures,
// read as "no failed logins".
func TestNoPromptFiltersEventsWithSearch(t *testing.T) {
	for name, text := range allPromptText() {
		if strings.Contains(text, "search=LOGIN_ERROR") {
			t.Errorf("%s still filters by search, which does not match event type; use types", name)
		}
	}
}

// The tools grew start_time and end_time. A prompt that says otherwise makes the
// model reconstruct a window client-side from whatever the default 24 hours
// returned, and report it as the requested period.
func TestNoPromptClaimsThereIsNoTimeFilter(t *testing.T) {
	for name, text := range allPromptText() {
		if strings.Contains(strings.ToLower(text), "no time filter") {
			t.Errorf("%s claims there is no time filter, but start_time and end_time exist", name)
		}
	}
}

// limit is refused above 100, so a prompt suggesting more is a guaranteed error.
func TestNoPromptSuggestsALimitOverTheCap(t *testing.T) {
	for name, text := range allPromptText() {
		for _, tok := range strings.FieldsFunc(text, func(r rune) bool {
			return r < '0' || r > '9'
		}) {
			n, err := strconv.Atoi(tok)
			if err != nil || n <= maxEventLimit {
				continue
			}
			// Only flag numbers presented as a limit, not years or ports.
			if strings.Contains(text, "limit="+tok) || strings.Contains(text, "start at "+tok) {
				t.Errorf("%s suggests limit %d, above the cap of %d, so the call errors", name, n, maxEventLimit)
			}
		}
	}
}

func TestFailedLoginPromptUsesTheTypeFilter(t *testing.T) {
	text := allPromptText()["triage_failed_logins"]
	for _, want := range []string{"types", "LOGIN_ERROR", "start_time"} {
		if !strings.Contains(text, want) {
			t.Errorf("failed-login prompt should mention %q so the model uses the real filters: %q", want, text)
		}
	}
}

func TestAdminChangePromptUsesTheRealFilters(t *testing.T) {
	text := allPromptText()["review_admin_changes"]
	for _, want := range []string{"start_time", "resource_type"} {
		if !strings.Contains(text, want) {
			t.Errorf("admin-change prompt should mention %q: %q", want, text)
		}
	}
}

// Admin events still carry no acting user. A prompt that asks "who did it"
// without saying so invites the model to invent an actor or silently omit the
// question it was asked.
func TestAdminChangePromptIsHonestAboutAttribution(t *testing.T) {
	text := strings.ToLower(allPromptText()["review_admin_changes"])
	if !strings.Contains(text, "client_id") {
		t.Errorf("admin-change prompt must say attribution is limited to client_id: %q", text)
	}
}

// The default for the prompt's own limit argument must also be servable.
func TestPromptLimitArgumentDefaultIsServable(t *testing.T) {
	for _, d := range promptDefs {
		for _, a := range d.prompt.Arguments {
			if a.Name != "limit" {
				continue
			}
			for _, tok := range strings.FieldsFunc(a.Description, func(r rune) bool { return r < '0' || r > '9' }) {
				if n, err := strconv.Atoi(tok); err == nil && n > maxEventLimit {
					t.Errorf("prompt %q advertises a default limit of %d, above the cap of %d", d.prompt.Name, n, maxEventLimit)
				}
			}
		}
	}
}
