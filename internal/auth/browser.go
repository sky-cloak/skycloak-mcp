package auth

import (
	"os/exec"
	"runtime"
)

// openBrowser opens url in the user's default browser. It returns an error if
// the platform is unsupported or the launcher cannot start, so callers fall
// back to printing the URL. It does not wait for the browser to exit.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default: // linux, *bsd
		return exec.Command("xdg-open", url).Start()
	}
}
