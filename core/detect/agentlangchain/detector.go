package agentlangchain

import (
	"context"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/agentframework"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "agentlangchain"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(ctx context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	return agentframework.DetectWithOptions(ctx, scope, agentframework.DetectorConfig{
		DetectorID: detectorID,
		Framework:  "langchain",
		ConfigPath: ".wrkr/agents/langchain.json",
		Format:     "json",
	}, options)
}
