package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// brandingRealmAPI answers CreateRealm with whatever the API would have said
// about default branding.
type brandingRealmAPI struct {
	stubAPI
	applied *bool
}

func (b brandingRealmAPI) CreateRealm(_ context.Context, _ string, r skycloak.Realm) (*skycloak.Realm, error) {
	r.DefaultBrandingApplied = b.applied
	r.Enabled = true
	return &r, nil
}

// The client mapping carrying this field proves nothing on its own: the tool
// builds its own summary, so the value has to survive that copy too. It did not,
// and no test noticed, because coverage stopped at the client.
func TestCreateRealmSurfacesDefaultBrandingApplied(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name string
		in   *bool
	}{{"applied", &yes}, {"skipped", &no}, {"unreported", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			_, out, err := createRealmHandler(brandingRealmAPI{applied: tc.in})(context.Background(), nil,
				CreateRealmInput{ClusterID: "c1", Name: "r"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch {
			case tc.in == nil && out.DefaultBrandingApplied != nil:
				t.Fatalf("got %v, want nil when the API said nothing", *out.DefaultBrandingApplied)
			case tc.in != nil && out.DefaultBrandingApplied == nil:
				t.Fatalf("the field was dropped between the client and the caller, want %v", *tc.in)
			case tc.in != nil && *out.DefaultBrandingApplied != *tc.in:
				t.Fatalf("got %v, want %v", *out.DefaultBrandingApplied, *tc.in)
			}
		})
	}
}

// The summary dropped everything but three fields, so a created realm came back
// claiming registration was disabled and belonging to no cluster.
func TestCreateRealmSummaryCarriesTheRealmItCreated(t *testing.T) {
	api := brandingRealmAPI{}
	_, out, err := createRealmHandler(api)(context.Background(), nil,
		CreateRealmInput{ClusterID: "c1", Name: "r", DisplayName: "R"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.ClusterID != "c1" {
		t.Errorf("cluster_id = %q, want the cluster it was created in", out.ClusterID)
	}
	if out.Name != "r" || out.DisplayName != "R" || !out.Enabled {
		t.Errorf("summary = %+v", out)
	}
}
