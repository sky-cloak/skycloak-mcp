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
	// WorkspaceID, if set, is used directly. Otherwise init tries to discover
	// the user's workspaces and uses the only one (or asks the user to pick).
	WorkspaceID string
	// AllowWrites requests write scopes in addition to read scopes, so the
	// minted key can back `skycloak-mcp run --allow-writes`.
	AllowWrites bool
	// TTL is the minted key's lifetime. Zero means no expiry.
	TTL time.Duration
}

// Init runs the interactive device sign-in: device authorization, workspace
// resolution, scope selection, API-key mint, and keychain storage. Human-facing
// progress is written to out; the API key itself is never printed.
func Init(ctx context.Context, cfg Config, opts InitOptions, out io.Writer) error {
	// One client for both polling and the API calls. Timeout is per-request, so
	// it bounds each device poll and each REST call without capping the overall
	// flow (the device code's own expiry does that).
	hc := &http.Client{Timeout: 30 * time.Second}

	fprintf(out, "Signing in to %s\n", cfg.Issuer)
	tok, err := deviceLogin(ctx, hc, cfg, func(p DevicePrompt) { printPrompt(out, p) })
	if err != nil {
		return err
	}
	fprintln(out, "Approved.")

	wsID, err := resolveWorkspace(ctx, hc, cfg, tok.AccessToken, opts.WorkspaceID, out)
	if err != nil {
		return err
	}

	scopes := resolveScopes(ctx, hc, cfg, tok.AccessToken, opts.AllowWrites)
	if len(scopes) == 0 {
		return fmt.Errorf("no scopes resolved; cannot create a key")
	}

	key, err := mintAPIKey(ctx, hc, cfg, tok.AccessToken, wsID, scopes, keyName(), opts.TTL)
	if err != nil {
		return err
	}
	if err := storeAPIKey(cfg, key); err != nil {
		return fmt.Errorf("store key in keychain: %w", err)
	}

	mode := "read-only"
	if opts.AllowWrites {
		mode = "read + write"
	}
	fprintf(out, "Done. Created a %s API key for workspace %s and saved it to your keychain.\n", mode, wsID)
	fprintln(out, "You can now run `skycloak-mcp run` (or point your MCP client at it). No key to paste.")
	return nil
}

// resolveWorkspace returns the workspace to scope the key to: the explicit id
// if given, the single discovered workspace, or an error listing the options.
func resolveWorkspace(ctx context.Context, hc *http.Client, cfg Config, token, explicit string, out io.Writer) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	wss, _ := listWorkspaces(ctx, hc, cfg, token)
	switch len(wss) {
	case 0:
		return "", fmt.Errorf("could not determine your workspace automatically; re-run with --workspace <id>")
	case 1:
		fprintf(out, "Using workspace %q (%s).\n", wss[0].Name, wss[0].ID)
		return wss[0].ID, nil
	default:
		fprintln(out, "You have multiple workspaces; re-run with --workspace <id>:")
		for _, w := range wss {
			fprintf(out, "  %s  %s\n", w.ID, w.Name)
		}
		return "", fmt.Errorf("multiple workspaces; choose one with --workspace <id>")
	}
}

// printPrompt shows the verification URL and user code. It prefers the complete
// URL (code embedded) so the user can one-click, and always prints the code as
// a fallback.
func printPrompt(out io.Writer, p DevicePrompt) {
	fprintln(out, "\nTo authorize, open this URL in your browser and confirm the code:")
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
