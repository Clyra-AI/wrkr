package workflowloc

import (
	"path/filepath"
	"strings"
)

func Normalize(path string) string {
	return strings.ToLower(filepath.ToSlash(strings.TrimSpace(path)))
}

func IsGitHubWorkflow(path string) bool {
	return strings.HasPrefix(Normalize(path), ".github/workflows/")
}

func IsJenkinsfile(path string) bool {
	return filepath.Base(Normalize(path)) == "jenkinsfile"
}

func IsGitLabEntryPipeline(path string) bool {
	normalized := Normalize(path)
	return normalized == ".gitlab-ci.yml" || normalized == ".gitlab-ci.yaml"
}

func IsGitLabCIPath(path string) bool {
	normalized := Normalize(path)
	if IsGitLabEntryPipeline(normalized) {
		return true
	}
	return strings.HasPrefix(normalized, ".gitlab/ci/") &&
		(strings.HasSuffix(normalized, ".yml") || strings.HasSuffix(normalized, ".yaml"))
}

func IsAzurePipelinePath(path string) bool {
	normalized := Normalize(path)
	base := filepath.Base(normalized)
	if base == "azure-pipelines.yml" || base == "azure-pipelines.yaml" {
		return true
	}
	return strings.HasPrefix(normalized, ".azure/pipelines/") &&
		(strings.HasSuffix(normalized, ".yml") || strings.HasSuffix(normalized, ".yaml"))
}

func IsCIWorkflow(path string) bool {
	return IsGitHubWorkflow(path) || IsJenkinsfile(path) || IsGitLabCIPath(path) || IsAzurePipelinePath(path)
}
