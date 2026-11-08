package skycloak

import (
	"context"
	"errors"
	"testing"
)

const fgaID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"

const fgaBody = `{"id":"` + fgaID + `","cluster_id":"` + cuid + `","realm":"my-service","status":"ready",` +
	`"api_url":"https://openfga-7c9e6679.eu.skycloak.io","issuer":"https://auth.example.com/realms/my-service",` +
	`"audience":"https://openfga-7c9e6679.eu.skycloak.io","created_at":"2026-11-05T10:00:00Z","updated_at":"2026-11-05T10:02:10Z"}`

func TestListOpenFGAInstancesIsClusterScoped(t *testing.T) {
	srv, method, _ := roleServer(t, 200, `{"instances":[`+fgaBody+`]}`)
	got, err := newTestClient(srv.URL).ListOpenFGAInstances(context.Background(), cuid)
	if err != nil {
		t.Fatalf("ListOpenFGAInstances: %v", err)
	}
	if *method != "GET /clusters/"+cuid+"/openfga-instances" {
		t.Errorf("unexpected request: %s", *method)
	}
	if len(got) != 1 || got[0].Realm != "my-service" || got[0].ClusterID != cuid || got[0].Audience == "" {
		t.Fatalf("mapped = %+v", got)
	}
}

func TestGetOpenFGAInstance(t *testing.T) {
	srv, method, _ := roleServer(t, 200, fgaBody)
	got, err := newTestClient(srv.URL).GetOpenFGAInstance(context.Background(), cuid, fgaID)
	if err != nil {
		t.Fatalf("GetOpenFGAInstance: %v", err)
	}
	if *method != "GET /clusters/"+cuid+"/openfga-instances/"+fgaID {
		t.Errorf("unexpected request: %s", *method)
	}
	if got.ID != fgaID || got.APIURL != "https://openfga-7c9e6679.eu.skycloak.io" || got.Issuer == "" {
		t.Fatalf("mapped = %+v", got)
	}
}

func TestCreateOpenFGAInstanceSendsRealmAndAccepts202(t *testing.T) {
	srv, method, sent := roleServer(t, 202, `{"id":"`+fgaID+`","cluster_id":"`+cuid+`","realm":"my-service","status":"provisioning","api_url":"https://x","issuer":"https://y","audience":"https://x","created_at":"2026-11-05T10:00:00Z","updated_at":"2026-11-05T10:00:00Z"}`)
	got, err := newTestClient(srv.URL).CreateOpenFGAInstance(context.Background(), cuid, "my-service")
	if err != nil {
		t.Fatalf("CreateOpenFGAInstance: %v", err)
	}
	if *method != "POST /clusters/"+cuid+"/openfga-instances" {
		t.Errorf("unexpected request: %s", *method)
	}
	if len(*sent) != 1 || (*sent)["realm"] != "my-service" {
		t.Fatalf("body = %v, want only realm", *sent)
	}
	if got.Status != "provisioning" {
		t.Fatalf("mapped = %+v", got)
	}
}

func TestCreateOpenFGAInstanceSurfacesConflict(t *testing.T) {
	srv, _, _ := roleServer(t, 409, `{"title":"The realm already has an OpenFGA instance","status":409}`)
	_, err := newTestClient(srv.URL).CreateOpenFGAInstance(context.Background(), cuid, "my-service")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 409 {
		t.Fatalf("want a 409 APIError, got %v", err)
	}
}

func TestDeleteOpenFGAInstanceReturnsTheDeletingInstance(t *testing.T) {
	srv, method, _ := roleServer(t, 202, `{"id":"`+fgaID+`","cluster_id":"`+cuid+`","realm":"my-service","status":"deleting","api_url":"https://x","issuer":"https://y","audience":"https://x","created_at":"2026-11-05T10:00:00Z","updated_at":"2026-11-05T10:00:00Z"}`)
	got, err := newTestClient(srv.URL).DeleteOpenFGAInstance(context.Background(), cuid, fgaID)
	if err != nil {
		t.Fatalf("DeleteOpenFGAInstance: %v", err)
	}
	if *method != "DELETE /clusters/"+cuid+"/openfga-instances/"+fgaID {
		t.Errorf("unexpected request: %s", *method)
	}
	if got == nil || got.Status != "deleting" {
		t.Fatalf("want the deleting instance, got %+v", got)
	}
}

func TestDeleteOpenFGAInstanceAlreadyGone(t *testing.T) {
	srv, _, _ := roleServer(t, 204, ``)
	got, err := newTestClient(srv.URL).DeleteOpenFGAInstance(context.Background(), cuid, fgaID)
	if err != nil || got != nil {
		t.Fatalf("204: want nil instance and no error, got %+v, %v", got, err)
	}
}
