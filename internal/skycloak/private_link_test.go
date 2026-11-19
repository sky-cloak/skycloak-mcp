package skycloak

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const privateLinkBody = `{"enabled":true,"azure_subscription_ids":["11111111-1111-1111-1111-111111111111"],"alias":"pls.alias","dns_name":"c1.private.example","status":"connected","connections":[{"subscription_id":"11111111-1111-1111-1111-111111111111","status":"connected"}]}`

func TestGetClusterPrivateLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/clusters/"+cuid+"/private-link" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, privateLinkBody)
	}))
	defer srv.Close()

	pl, err := newTestClient(srv.URL).GetClusterPrivateLink(t.Context(), cuid)
	if err != nil {
		t.Fatal(err)
	}
	if !pl.Enabled || pl.Alias != "pls.alias" || pl.DNSName != "c1.private.example" || pl.Status != "connected" {
		t.Fatalf("unexpected private link: %+v", pl)
	}
	if len(pl.AzureSubscriptionIDs) != 1 || len(pl.Connections) != 1 || pl.Connections[0].Status != "connected" {
		t.Fatalf("unexpected lists: %+v", pl)
	}
}

func TestGetClusterPrivateLinkKeepsTheRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 422, `{"detail":"site has no Azure private link"}`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).GetClusterPrivateLink(t.Context(), cuid)
	apiErr, ok := AsAPIError(err)
	if !ok || apiErr.StatusCode != 422 || apiErr.Problem.Detail != "site has no Azure private link" {
		t.Fatalf("err = %v", err)
	}
}

// privateLinkServer answers the read with the cluster's current state and
// records the PUT body, so a test can assert what went over the wire.
func privateLinkServer(t *testing.T, currentEnabled bool, readStatus int) (*httptest.Server, *map[string]any, *int) {
	t.Helper()
	var body map[string]any
	reads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reads++
			if readStatus != 200 {
				writeJSON(w, readStatus, `{"detail":"refused"}`)
				return
			}
			if currentEnabled {
				writeJSON(w, 200, privateLinkBody)
			} else {
				writeJSON(w, 200, `{"enabled":false,"azure_subscription_ids":[],"status":"disabled"}`)
			}
			return
		}
		b, _ := io.ReadAll(r.Body)
		body = nil
		_ = json.Unmarshal(b, &body)
		writeJSON(w, 200, privateLinkBody)
	}))
	t.Cleanup(srv.Close)
	return srv, &body, &reads
}

// The API requires enabled on every update. When the caller does not say, the
// client sends the cluster's current value, so changing the subscription list
// never switches private link on or off by accident.
func TestUpdateClusterPrivateLinkKeepsTheCurrentEnabledState(t *testing.T) {
	for _, current := range []bool{true, false} {
		srv, body, _ := privateLinkServer(t, current, 200)
		ids := []string{"22222222-2222-2222-2222-222222222222"}
		if _, err := newTestClient(srv.URL).UpdateClusterPrivateLink(t.Context(), cuid, &ids, nil); err != nil {
			t.Fatal(err)
		}
		if got := (*body)["enabled"]; got != current {
			t.Errorf("current=%v: enabled sent as %v", current, got)
		}
		if got, _ := (*body)["azure_subscription_ids"].([]any); len(got) != 1 {
			t.Errorf("current=%v: subscription list sent as %v", current, (*body)["azure_subscription_ids"])
		}
	}
}

func TestUpdateClusterPrivateLinkUsesAnExplicitFlagWithoutReading(t *testing.T) {
	srv, body, reads := privateLinkServer(t, true, 200)
	off := false
	if _, err := newTestClient(srv.URL).UpdateClusterPrivateLink(t.Context(), cuid, nil, &off); err != nil {
		t.Fatal(err)
	}
	if *reads != 0 {
		t.Errorf("read the current state %d times though enabled was given", *reads)
	}
	if (*body)["enabled"] != false {
		t.Errorf("enabled sent as %v", (*body)["enabled"])
	}
	if _, present := (*body)["azure_subscription_ids"]; present {
		t.Errorf("an omitted list was sent: %v", (*body)["azure_subscription_ids"])
	}
}

func TestUpdateClusterPrivateLinkSendsAnEmptyListToClearIt(t *testing.T) {
	srv, body, _ := privateLinkServer(t, true, 200)
	if _, err := newTestClient(srv.URL).UpdateClusterPrivateLink(t.Context(), cuid, &[]string{}, nil); err != nil {
		t.Fatal(err)
	}
	if got, ok := (*body)["azure_subscription_ids"].([]any); !ok || len(got) != 0 {
		t.Errorf("subscription list sent as %v, want an empty array", (*body)["azure_subscription_ids"])
	}
}

// A refused read must not fall back to enabled=false: that would switch private
// link off on a cluster the caller only meant to re-list.
func TestUpdateClusterPrivateLinkRefusesToWriteWhenTheReadFails(t *testing.T) {
	srv, body, _ := privateLinkServer(t, true, 403)
	if _, err := newTestClient(srv.URL).UpdateClusterPrivateLink(t.Context(), cuid, &[]string{}, nil); err == nil {
		t.Fatal("the update succeeded despite being unable to read the current state")
	}
	if *body != nil {
		t.Fatalf("an update was sent after the read was refused: %v", *body)
	}
}

func TestUpdateClusterPrivateLinkKeepsTheRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 409, `{"detail":"turn public access back on first"}`)
	}))
	defer srv.Close()
	off := false
	_, err := newTestClient(srv.URL).UpdateClusterPrivateLink(t.Context(), cuid, nil, &off)
	apiErr, ok := AsAPIError(err)
	if !ok || apiErr.StatusCode != 409 {
		t.Fatalf("err = %v", err)
	}
}
