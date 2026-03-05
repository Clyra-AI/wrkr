package agentllamaindex

import (
	"context"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/agentframework"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "agentllamaindex"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(ctx context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	return agentframework.Detect(ctx, scope, agentframework.DetectorConfig{
		DetectorID: detectorID,
		Framework:  "llamaindex",
		ConfigPath: ".wrkr/agents/llamaindex.yaml",
		Format:     "yaml",
	})
}
