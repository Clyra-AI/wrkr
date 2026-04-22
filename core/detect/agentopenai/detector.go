package agentopenai

import (
	"context"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/agentframework"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "agentopenai"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(ctx context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	return agentframework.DetectWithOptions(ctx, scope, agentframework.DetectorConfig{
		DetectorID: detectorID,
		Framework:  "openai_agents",
		ConfigPath: ".wrkr/agents/openai-agents.json",
		Format:     "json",
	}, options)
}
