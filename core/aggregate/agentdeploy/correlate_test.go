package agentdeploy

import (
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestAgentDeploymentCorrelator_MatchesArtifactsDeterministically(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "langchain",
			Location:    "agents/release.py",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "release_agent"},
				{Key: "deployment_artifacts", Value: ".github/workflows/release.yml"},
			},
		},
	}

	first := Resolve(findings)
	second := Resolve(findings)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic correlation output\nfirst=%+v\nsecond=%+v", first, second)
	}

	instanceID := identity.AgentInstanceID("langchain", "agents/release.py", "release_agent", 0, 0)
	deployment := first[instanceID]
	if deployment.DeploymentStatus != "deployed" {
		t.Fatalf("expected deployed status, got %q", deployment.DeploymentStatus)
	}
	if !reflect.DeepEqual(deployment.DeploymentArtifacts, []string{".github/workflows/release.yml"}) {
		t.Fatalf("unexpected deployment artifacts: %+v", deployment.DeploymentArtifacts)
	}
}

func TestAgentDeploymentCorrelator_AmbiguousPathFailClosed(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "crewai",
			Location:    "agents/ops.py",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "ops_agent"},
				{Key: "deployment_artifacts", Value: "Dockerfile,.github/workflows/deploy.yml"},
			},
		},
	}

	instanceID := identity.AgentInstanceID("crewai", "agents/ops.py", "ops_agent", 0, 0)
	deployment := Resolve(findings)[instanceID]
	if deployment.DeploymentStatus != "ambiguous" {
		t.Fatalf("expected ambiguous status, got %q", deployment.DeploymentStatus)
	}
	if !reflect.DeepEqual(deployment.DeploymentArtifacts, []string{".github/workflows/deploy.yml", "Dockerfile"}) {
		t.Fatalf("expected deterministic ambiguous artifacts, got %+v", deployment.DeploymentArtifacts)
	}
}
