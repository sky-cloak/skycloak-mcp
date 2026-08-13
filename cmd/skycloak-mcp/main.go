// Command skycloak-mcp is the official Skycloak Model Context Protocol server.
// It exposes the Skycloak public API as MCP tools so an AI assistant can manage
// a customer's managed-Keycloak environment.
//
// Local stdio authentication uses an OAuth 2.0 device sign-in:
//
//	skycloak-mcp init     sign in once (device flow); stores a workspace-scoped
//	                      API key in the OS keychain
//	skycloak-mcp run      run the MCP server (stdio | http)
//	skycloak-mcp logout   remove the stored key
//
// For stdio, setting SKYCLOAK_API_KEY skips the keychain entirely (for CI /
// headless use). The HTTP transport holds no key of its own: each request
// carries its caller's, as `Authorization: Bearer <key>` or `API-Key: <key>`.
// Invoking with server flags but no subcommand behaves like `run`, so existing
// `skycloak-mcp --transport stdio` configurations keep working.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/term"

	"github.com/sky-cloak/skycloak-mcp/internal/auth"
	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
	"github.com/sky-cloak/skycloak-mcp/internal/tools"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx := context.Background()
	args := os.Args[1:]

	if len(args) > 0 {
		switch args[0] {
		case "--version", "-version", "version":
			fmt.Println(version)
			return
		case "init":
			os.Exit(runInit(ctx, args[1:]))
		case "logout":
			os.Exit(runLogout())
		case "run":
			args = args[1:] // fall through to the server with the rest of the flags
		}
	}
	runServer(ctx, args)
}

// runInit performs the interactive device sign-in and stores the minted key.
func runInit(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("skycloak-mcp init", flag.ExitOnError)
	workspace := fs.String("workspace", "", "workspace ID to scope the key to (auto-detected if omitted)")
	allowWrites := fs.Bool("allow-writes", false, "also request write scopes (for `run --allow-writes`)")
	ttlDays := fs.Int("ttl-days", 90, "lifetime of the minted key in days (0 = no expiry)")
	noBrowser := fs.Bool("no-browser", false, "print the verification URL instead of opening a browser")
	_ = fs.Parse(args)

	cfg := auth.ConfigFromEnv()
	opts := auth.InitOptions{
		WorkspaceID: *workspace,
		AllowWrites: *allowWrites,
		TTL:         time.Duration(*ttlDays) * 24 * time.Hour,
		NoBrowser:   *noBrowser,
	}
	if err := auth.Init(ctx, cfg, opts, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "init failed: %v\n", err)
		return 1
	}
	return 0
}

// runLogout removes the stored credential.
func runLogout() int {
	if err := auth.Logout(auth.ConfigFromEnv()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "logout failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(os.Stderr, "Signed out; stored key removed.")
	return 0
}

// runServer parses the server flags and serves the chosen transport.
func runServer(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("skycloak-mcp", flag.ExitOnError)
	transport := fs.String("transport", "stdio", "transport: stdio | http")
	httpAddr := fs.String("http-addr", ":8080", "listen address for the http transport")
	allowWrites := fs.Bool("allow-writes", false, "enable mutating tools (requires a write-scoped key)")
	showVersion := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(args)

	if *showVersion {
		fmt.Println(version)
		return
	}

	endpoint := getenv("SKYCLOAK_ENDPOINT", "https://api.skycloak.io")
	apiVersion := getenv("SKYCLOAK_API_VERSION", "2026-06-01.beta")
	userAgent := "skycloak-mcp/" + version

	switch *transport {
	case "stdio":
		cfg := auth.ConfigFromEnv()
		apiKey, err := auth.LoadAPIKey(cfg)
		if errors.Is(err, auth.ErrNoCredential) && term.IsTerminal(int(os.Stdin.Fd())) {
			// A human ran `run` directly with no stored key: sign in inline, then
			// reload. When an MCP client spawns us (stdin is a pipe, not a TTY) we
			// skip this and surface the actionable "run init" error instead, since
			// the browser device flow can't be driven over the protocol pipe.
			if ierr := auth.Init(ctx, cfg, auth.InitOptions{AllowWrites: *allowWrites, TTL: 90 * 24 * time.Hour}, os.Stderr); ierr != nil {
				log.Fatalf("sign-in failed: %v", ierr)
			}
			apiKey, err = auth.LoadAPIKey(cfg)
		}
		if err != nil {
			log.Fatalf("%v", err)
		}
		client := skycloak.New(endpoint, apiKey, apiVersion, skycloak.WithUserAgent(userAgent))
		server := newMCPServer(client, *allowWrites)
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatalf("server error: %v", err)
		}
	case "http":
		handler := newHTTPHandler(httpConfig{endpoint: endpoint, apiVersion: apiVersion, userAgent: userAgent, allowWrites: *allowWrites})
		srv := newHTTPServer(*httpAddr, handler)
		ln, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			log.Fatalf("listen %s: %v", *httpAddr, err)
		}
		signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		log.Printf("skycloak-mcp %s listening on %s (streamable HTTP)", version, ln.Addr())
		if err := serveWithShutdown(signalCtx, srv, ln); err != nil {
			log.Fatalf("server error: %v", err)
		}
	default:
		log.Fatalf("unknown transport %q (want stdio|http)", *transport)
	}
}

func newMCPServer(api tools.API, allowWrites bool) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "skycloak-mcp", Version: version}, nil)
	tools.Register(server, api, allowWrites)
	return server
}

// httpConfig holds what the HTTP transport needs to build a per-caller client.
type httpConfig struct {
	endpoint    string
	apiVersion  string
	userAgent   string
	allowWrites bool
}

// newHTTPHandler serves MCP over streamable HTTP, authenticating every request
// individually.
//
// It runs stateless. Otherwise the SDK caches a session — and the server built
// for it — under the client-supplied Mcp-Session-Id, consulting the credential
// only when that session is first created, so anyone replaying the id would act
// with the original caller's key. The SDK's own guard binds sessions to
// auth.TokenInfo, which only its bearer middleware can populate, so a custom
// credential header leaves the guard permanently disarmed. Holding no session
// state removes the attack surface, and lets any replica serve any request
// without sticky sessions.
func newHTTPHandler(cfg httpConfig) http.Handler {
	cache := newServerCache(defaultServerCacheSize, defaultServerCacheTTL,
		func(apiKey string, allowWrites bool) *mcp.Server {
			api := skycloak.New(cfg.endpoint, apiKey, cfg.apiVersion, skycloak.WithUserAgent(cfg.userAgent))
			return newMCPServer(api, allowWrites)
		})

	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		apiKey, err := credentialFromRequest(r)
		if err != nil {
			return nil
		}
		readonly, err := readonlyMode(r)
		if err != nil {
			return nil
		}
		return cache.get(apiKey, httpAllowWrites(cfg.allowWrites, readonly))
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	authed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := readonlyMode(r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := credentialFromRequest(r); err != nil {
			// 401 (not 400) so clients can distinguish "authenticate" from
			// "malformed"; the challenge tells them which scheme to use.
			w.Header().Set("WWW-Authenticate", `Bearer realm="skycloak-mcp"`)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})

	// Probes cannot present a credential, so health lives outside the auth
	// wrapper. Both report the same thing: the process is up. There is no
	// readiness to gate on — the server holds no connection and no state, and a
	// dependency check here would only turn a Skycloak API blip into a
	// self-inflicted outage by failing every replica's probe at once.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleHealth)
	mux.Handle("/", authed)
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// errNoCredential is returned when a request carries neither supported header.
var errNoCredential = errors.New("missing credential: send `Authorization: Bearer <api-key>` or `API-Key: <api-key>`")

// credentialFromRequest extracts the caller's Skycloak API key. Bearer is the
// MCP-standard shape and is preferred; API-Key matches the Skycloak REST API.
// The key's validity is not checked here — the Skycloak API is the authority,
// and verifying up front would cost a round trip on every request.
func credentialFromRequest(r *http.Request) (string, error) {
	if fields := strings.Fields(r.Header.Get("Authorization")); len(fields) == 2 {
		if strings.EqualFold(fields[0], "bearer") {
			if key := strings.TrimSpace(fields[1]); key != "" {
				return key, nil
			}
		}
	}
	if key := strings.TrimSpace(r.Header.Get("API-Key")); key != "" {
		return key, nil
	}
	return "", errNoCredential
}

// httpAllowWrites returns true if the server is configured to allow writes and
// the session is not in readonly mode.
func httpAllowWrites(serverAllowWrites, readonly bool) bool {
	return serverAllowWrites && !readonly
}

// readonlyMode returns true if the request has a query parameter
// `readonly=true`.
func readonlyMode(r *http.Request) (bool, error) {
	values, ok := r.URL.Query()["readonly"]
	if !ok {
		return false, nil
	}
	raw := values[len(values)-1]
	switch raw {
	case "true", "false":
		return raw == "true", nil
	default:
		return false, fmt.Errorf("invalid readonly query parameter %q (want true or false)", raw)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
