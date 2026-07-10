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
	return strings.HasSuffix(filepath.Base(os.Args[0]), ".test")
}
