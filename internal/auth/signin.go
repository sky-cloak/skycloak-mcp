package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// InitOptions tunes the interactive sign-in.
type InitOptions struct {
	// WorkspaceID, if set, overrides the server's default-workspace resolution.
	// Otherwise the server scopes the key to the caller's default workspace.
	WorkspaceID string
	// AllowWrites requests write scopes in addition to read scopes, so the
	// minted key can back `skycloak-mcp run --allow-writes`.
	AllowWrites bool
	// AllowCredentials additionally requests clusters:credentials:read, which
	// lets skycloak_get_cluster_credentials return a cluster's Keycloak admin
	// credentials. Off by default: without it that tool is the only one a
	// signed-in user cannot call.
	AllowCredentials bool
	// TTL is the minted key's lifetime. Zero means no expiry.
	TTL time.Duration
	// NoBrowser prints the verification URL instead of opening it in a browser.
	NoBrowser bool
}

// Init runs the interactive device sign-in: device authorization, then mints a
// workspace-scoped key via the dashboard's Bearer endpoint and stores it in the
// keychain. Human-facing progress is written to out; the key is never printed.
func Init(ctx context.Context, cfg Config, opts InitOptions, out io.Writer) error {
	// One client for both polling and the API calls. Timeout is per-request, so
	// it bounds each device poll and each REST call without capping the overall
	// flow (the device code's own expiry does that).
	hc := &http.Client{Timeout: 30 * time.Second}

	fprintf(out, "Signing in to %s\n", cfg.Issuer)
	// The browser consent page can only list Keycloak's own scopes (openid,
	// profile, email); the key's actual powers are chosen here, in the mint
	// request. State them before the user approves, so the approval is informed.
	printGrantNotice(out, opts)
	tok, err := deviceLogin(ctx, hc, cfg, func(p DevicePrompt) {
		url := p.VerificationURIComplete
		if url == "" {
			url = p.VerificationURI
		}
		if !opts.NoBrowser && openBrowser(url) == nil {
			fprintln(out, "\nOpened your browser to approve the sign-in. If it did not open, use:")
		} else {
			fprintln(out, "\nTo authorize, open this URL in your browser and confirm the code:")
		}
		printPrompt(out, p)
	})
	if err != nil {
		return err
	}
	fprintln(out, "Approved.")

	fullKey, wsID, err := mintCLIKey(ctx, hc, cfg, tok.AccessToken, opts)
	if err != nil {
		return err
	}
	if err := storeAPIKey(cfg, fullKey); err != nil {
		return fmt.Errorf("store key in keychain: %w", err)
	}

	mode := "read-only"
	if opts.AllowWrites {
		mode = "read + write"
	}
	if opts.AllowCredentials {
		mode += " + cluster credentials"
	}
	if wsID != "" {
		fprintf(out, "Done. Created a %s API key for workspace %s and saved it to your keychain.\n", mode, wsID)
	} else {
		fprintf(out, "Done. Created a %s API key and saved it to your keychain.\n", mode)
	}
	fprintln(out, "You can now run `skycloak-mcp run` (or point your MCP client at it). No key to paste.")
	return nil
}

// printPrompt shows the verification URL and user code. It prefers the complete
// URL (code embedded) so the user can one-click, and always prints the code as
// a fallback.
// printGrantNotice states what the minted key will be able to do. The browser
// consent screen cannot show this: API key scopes are a Skycloak concept, not
// Keycloak client scopes, so they never reach Keycloak's consent page.
func printGrantNotice(out io.Writer, opts InitOptions) {
	if opts.AllowWrites {
		fprintf(out, "\nThis will create an API key that can READ AND MODIFY your Skycloak\nresources (clusters, realms, applications, users, identity providers).\n")
	} else {
		fprintf(out, "\nThis will create a read-only API key. Re-run with --allow-writes to\ninclude write access.\n")
	}
	if opts.AllowCredentials {
		fprintf(out, "It will ALSO be able to read your clusters' Keycloak admin credentials,\nwhich an assistant using this key can then see.\n")
	}
	if opts.TTL > 0 {
		fprintf(out, "The key expires in %s.\n", opts.TTL)
	} else {
		fprintf(out, "The key does not expire. Pass --ttl to set a lifetime, and revoke it\nany time from the dashboard.\n")
	}
}

func printPrompt(out io.Writer, p DevicePrompt) {
	if p.VerificationURIComplete != "" {
		fprintf(out, "  %s\n", p.VerificationURIComplete)
	}
	fprintf(out, "  URL:  %s\n", p.VerificationURI)
	fprintf(out, "  Code: %s\n", p.UserCode)
	if !p.ExpiresAt.IsZero() {
		fprintf(out, "  (expires in about %d minutes)\n", int(time.Until(p.ExpiresAt).Minutes()))
	}
	fprintln(out, "Waiting for approval...")
}

// keyName labels the minted key so it is recognizable in the dashboard.
func keyName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "skycloak-mcp"
	}
	return "skycloak-mcp@" + host
}

// fprintf / fprintln write human-facing progress and intentionally ignore write
// errors (stderr/stdout failures are not actionable here).
func fprintf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
func fprintln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }
