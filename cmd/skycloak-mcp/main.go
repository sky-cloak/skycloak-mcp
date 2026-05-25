// Command skycloak-mcp is the official Skycloak Model Context Protocol server.
// It exposes the Skycloak public API as MCP tools so an AI assistant can manage
// a customer's managed-Keycloak environment, authenticated with their API key.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
	"github.com/sky-cloak/skycloak-mcp/internal/tools"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	transport := flag.String("transport", "stdio", "transport: stdio | http")
	httpAddr := flag.String("http-addr", ":8080", "listen address for the http transport")
	allowWrites := flag.Bool("allow-writes", false, "enable mutating tools (requires a write-scoped API key)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	apiKey := os.Getenv("SKYCLOAK_API_KEY")
	if apiKey == "" {
		log.Fatal("SKYCLOAK_API_KEY is required")
	}
	endpoint := getenv("SKYCLOAK_ENDPOINT", "https://api.skycloak.io")
	apiVersion := os.Getenv("SKYCLOAK_API_VERSION")

	client := skycloak.New(endpoint, apiKey, apiVersion, skycloak.WithUserAgent("skycloak-mcp/"+version))

	server := mcp.NewServer(&mcp.Implementation{Name: "skycloak-mcp", Version: version}, nil)
	tools.Register(server, client, *allowWrites)

	ctx := context.Background()
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
