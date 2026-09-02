package tools

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The canned prompts are instructions a model follows literally, so a stale one
// is worse than stale docs: it steers every caller into a call that fails or
// silently answers wrong. These pin them to what the tools actually do now.

// allPromptText renders every prompt in the registry. Hand-listing a few left
// the rest unguarded, so a stale line added to any other prompt, or a new prompt
// carrying one, would pass unnoticed.
func allPromptText() map[string]string {
	args := map[string]string{
		"realm": "alfred", "cluster_id": "c1", "cluster_name": "prod",
		"domain": "auth.example.com", "window": "the last 7 days",
		"client_id": "web", "alias": "google", "name": "prod",
	}
	out := map[string]string{}
	for _, d := range promptDefs {
		if d.text == nil {
			continue
		}
		out[d.prompt.Name] = d.text(args)
		// Descriptions are read by a model choosing a workflow, so they go
		// stale the same way the bodies do.
		out[d.prompt.Name+" (description)"] = d.prompt.Description
	}
	return out
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

// limit is refused above 100, so any number a prompt presents as a limit is a
// guaranteed error. Matching only "limit=N" and "start at N" let "capped at
// 1000" through, which teaches the wrong cap just as effectively.
func TestNoPromptSuggestsALimitOverTheCap(t *testing.T) {
	// Any number appearing within a few words of limit-ish wording.
	near := regexp.MustCompile(`(?i)(limit\D{0,24}|cap(?:ped)?\D{0,24}|pull\D{0,16}|start at\s+)(\d+)`)
	for name, text := range allPromptText() {
		for _, m := range near.FindAllStringSubmatch(text, -1) {
			n, err := strconv.Atoi(m[2])
			if err != nil || n <= maxEventLimit {
				continue
			}
			t.Errorf("%s presents %d as a limit, above the cap of %d, so the call is refused (in %q)",
				name, n, maxEventLimit, strings.TrimSpace(m[0]))
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

// Admin events still carry no acting user. Asserting only that "client_id"
// appears let a prompt saying "attribute every change to the admin username
// recorded in client_id" pass — the opposite claim, and exactly the fabricated
// attribution this is meant to prevent.
func TestAdminChangePromptIsHonestAboutAttribution(t *testing.T) {
	text := strings.ToLower(allPromptText()["review_admin_changes"])
	if !strings.Contains(text, "no acting user") {
		t.Errorf("admin-change prompt must state that no acting user is recorded: %q", text)
	}
	if !strings.Contains(text, "do not infer") && !strings.Contains(text, "do not guess") {
		t.Errorf("admin-change prompt must forbid inferring an actor: %q", text)
	}
	// The phrasings that would put a name on an unattributed change.
	for _, bad := range []string{"username recorded in client_id", "attribute every change"} {
		if strings.Contains(text, bad) {
			t.Errorf("admin-change prompt invites a fabricated actor via %q", bad)
		}
	}
}

// A description is what a model reads when choosing a workflow, so it makes the
// same promise the body does. Checking only the body let the description keep
// advertising "who changed what" after the body had been corrected.
func TestNoPromptDescriptionPromisesAnActor(t *testing.T) {
	promises := regexp.MustCompile(`(?i)\b(who changed|who did|by whom)\b`)
	for _, d := range promptDefs {
		if !strings.Contains(strings.ToLower(d.prompt.Description), "admin") &&
			!strings.Contains(strings.ToLower(d.prompt.Name), "admin") {
			continue
		}
		if m := promises.FindString(d.prompt.Description); m != "" {
			t.Errorf("prompt %q description promises %q, which admin events do not record: %q",
				d.prompt.Name, m, d.prompt.Description)
		}
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

// The skills ship the same kind of instructions as the prompts and go stale the
// same way. Nothing checked them, which is how auth-incident-triage kept telling
// callers to pull "a generous limit" and to report who made an admin change
// after the prompts had been corrected on both counts.
func TestSkillsDoNotEncodeRemovedBehaviour(t *testing.T) {
	root := filepath.Join("skills")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		lower := strings.ToLower(text)

		for _, bad := range []string{"search=login_error", "no time filter", "generous limit"} {
			if strings.Contains(lower, bad) {
				t.Errorf("%s: %q describes behaviour the tools no longer have", path, bad)
			}
		}
		// Any number presented as a limit must be servable.
		near := regexp.MustCompile(`(?i)(limit\D{0,24}|cap(?:ped)?\D{0,24}|start at\s+)(\d+)`)
		for _, m := range near.FindAllStringSubmatch(text, -1) {
			if n, err := strconv.Atoi(m[2]); err == nil && n > maxEventLimit {
				t.Errorf("%s presents %d as a limit, above the cap of %d", path, n, maxEventLimit)
			}
		}
		// A skill that reads admin events must not promise an actor. Matched on
		// the promise itself, not the word: "not by whom" is the correction and
		// must pass, while "shows by whom" is the claim and must not.
		if strings.Contains(lower, "category=admin") {
			promises := regexp.MustCompile(`(?i)(report who, what and when|(?:shows?|carries|records)\s+(?:\S+\s+){0,2}by whom)`)
			if m := promises.FindString(text); m != "" {
				t.Errorf("%s promises attribution admin events do not carry: %q", path, strings.TrimSpace(m))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk skills: %v", err)
	}
}
