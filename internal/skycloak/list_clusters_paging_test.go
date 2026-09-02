package skycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ListClusters took a ListClustersParams and discarded it, so limit and offset
// were advertised on the tool, set by callers, and silently ignored. That is
// the failure this codebase keeps having to remove: a filter the caller
// believes applied. The API has no paging on /clusters, so it is applied here.

func clustersServer(t *testing.T, n int) *httptest.Server {
	t.Helper()
	body := "["
	for i := range n {
		if i > 0 {
			body += ","
		}
		body += `{"id":"` + uuidForIndex(i) + `","name":"c` + itoa(i) + `","status":"available"}`
	}
	body += "]"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, body)
	}))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	return out
}

// uuidForIndex builds a distinct, well-formed UUID per index.
func uuidForIndex(i int) string {
	hex := "0123456789abcdef"
	return "00000000-0000-4000-8000-0000000000" + string(hex[(i/16)%16]) + string(hex[i%16])
}

func TestListClustersAppliesLimit(t *testing.T) {
	srv := clustersServer(t, 10)
	defer srv.Close()

	got, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{Limit: 3})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("limit ignored: got %d clusters, want 3", len(got))
	}
	if got[0].Name != "c0" {
		t.Errorf("limit should take from the start, got %q", got[0].Name)
	}
}

func TestListClustersAppliesOffset(t *testing.T) {
	srv := clustersServer(t, 10)
	defer srv.Close()

	got, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{Offset: 7})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("offset ignored: got %d clusters, want 3", len(got))
	}
	if got[0].Name != "c7" {
		t.Errorf("offset should skip from the start, got %q", got[0].Name)
	}
}

func TestListClustersPagesWithoutGapOrOverlap(t *testing.T) {
	srv := clustersServer(t, 10)
	defer srv.Close()
	c := newTestClient(srv.URL)

	first, err := c.ListClusters(context.Background(), ListClustersParams{Limit: 4})
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	second, err := c.ListClusters(context.Background(), ListClustersParams{Limit: 4, Offset: 4})
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(first) != 4 || len(second) != 4 {
		t.Fatalf("page sizes: %d, %d", len(first), len(second))
	}
	if first[3].Name != "c3" || second[0].Name != "c4" {
		t.Errorf("pages must abut exactly: %q then %q", first[3].Name, second[0].Name)
	}
}

// An offset past the end is an empty page, not an error and not a wrapped
// first page.
func TestListClustersOffsetPastEndIsEmpty(t *testing.T) {
	srv := clustersServer(t, 3)
	defer srv.Close()

	got, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{Offset: 99})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("offset past the end returned %d clusters", len(got))
	}
}

// No paging asked for means everything, which is what callers get today. A
// default limit applied here would silently truncate every existing caller.
func TestListClustersWithoutParamsReturnsEverything(t *testing.T) {
	srv := clustersServer(t, 30)
	defer srv.Close()

	got, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(got) != 30 {
		t.Fatalf("unpaged call returned %d, want all 30", len(got))
	}
}

// A negative offset is a caller mistake, not a request for page one, matching
// how QueryEvents treats it.
func TestListClustersRejectsNegativeOffset(t *testing.T) {
	srv := clustersServer(t, 3)
	defer srv.Close()

	if _, err := newTestClient(srv.URL).ListClusters(context.Background(),
		ListClustersParams{Offset: -1}); err == nil {
		t.Fatal("negative offset accepted")
	}
}
