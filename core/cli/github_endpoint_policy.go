package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/wrkr/internal/githubendpoint"
)

const insecureLoopbackGitHubEnv = "WRKR_ALLOW_INSECURE_LOOPBACK_GITHUB"

func githubEndpointOptions() githubendpoint.Options {
	return githubendpoint.Options{AllowInsecureLoopback: isDevelopmentTestProcess() || strings.TrimSpace(os.Getenv(insecureLoopbackGitHubEnv)) == "1"}
}

func isDevelopmentTestProcess() bool {
	name := strings.ToLower(filepath.Base(os.Args[0]))
	return strings.HasSuffix(name, ".test") || strings.HasSuffix(name, ".test.exe")
}
