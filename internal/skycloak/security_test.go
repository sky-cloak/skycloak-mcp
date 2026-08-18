package skycloak

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// UpdateClusterSecurity is a read-modify-write: it reads the current config so
// the sections it does not manage, CAPTCHA in particular, survive the update.
// If the read is refused, continuing would send an empty body and wipe them.
func TestUpdateClusterSecurityRefusesToWriteWhenTheReadFails(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusForbidden, `{"error":"missing scope clusters:security:read"}`)
			return
		}
		wrote = true
		writeJSON(w, http.StatusOK, `{}`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).UpdateClusterSecurity(t.Context(), cuid, &ClusterSecurity{})
	if err == nil {
		t.Fatal("the update succeeded despite being unable to read the current config")
	}
	if wrote {
		t.Fatal("an update was sent after the read was refused; it would have wiped the unmanaged sections")
	}
}
