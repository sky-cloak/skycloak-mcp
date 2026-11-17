package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestStdioServesToolsWithoutCredentials builds the binary and drives a real
// stdio session against it with no credential of any kind.
//
// This is how a server directory introspects us: build the image, run it with
// no environment, send initialize and tools/list. The container has no OS
// keychain (distroless has no D-Bus), so loading a key fails outright rather
// than merely finding nothing, and the server used to exit on that before it
// had answered anything. A directory then records a server with no tools.
func TestStdioServesToolsWithoutCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the credential-less path is about the Linux/container keychain")
	}

	bin := filepath.Join(t.TempDir(), "skycloak-mcp")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.Command(bin, "run", "--transport", "stdio")
	// An empty environment, not the test process's: inheriting SKYCLOAK_API_KEY
	// from a developer's shell would hide exactly the failure this covers.
	// HOME is set because a keychain backend may probe it, and an unset HOME is
	// a different failure from an unreachable keychain.
	cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	cmd.Stderr = os.Stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "no-credential-probe", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("initialize with no credential: %v", err)
	}
	defer func() { _ = session.Close() }()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list with no credential: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("tools/list returned no tools; a directory would record this server as having none")
	}
}
