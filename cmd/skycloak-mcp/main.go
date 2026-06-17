// Command skycloak-mcp is the official Skycloak Model Context Protocol server.
// It exposes the Skycloak public API as MCP tools so an AI assistant can manage
// a customer's managed-Keycloak environment.
//
// Authentication uses an OAuth 2.0 device sign-in:
//
//	skycloak-mcp init     sign in once (device flow); stores a workspace-scoped
//	                      API key in the OS keychain
//	skycloak-mcp run      run the MCP server (stdio | http) using the stored key
//	skycloak-mcp logout   remove the stored key
//
// Setting SKYCLOAK_API_KEY skips the keychain entirely (for CI / headless use),
// and invoking with server flags but no subcommand behaves like `run`, so
// existing `skycloak-mcp --transport stdio` configurations keep working.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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

// runServer parses the server flags, loads the API key, and serves the chosen
// transport.
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
	endpoint := getenv("SKYCLOAK_ENDPOINT", "https://api.skycloak.io")
	apiVersion := os.Getenv("SKYCLOAK_API_VERSION")

	client := skycloak.New(endpoint, apiKey, apiVersion, skycloak.WithUserAgent("skycloak-mcp/"+version))

	server := mcp.NewServer(&mcp.Implementation{Name: "skycloak-mcp", Version: version}, nil)
	tools.Register(server, client, *allowWrites)

	switch *transport {
	case "stdio":
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatalf("server error: %v", err)
		}
	case "http":
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
		log.Printf("skycloak-mcp %s listening on %s (streamable HTTP)", version, *httpAddr)
		srv := &http.Server{Addr: *httpAddr, Handler: handler}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	default:
		log.Fatalf("unknown transport %q (want stdio|http)", *transport)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
