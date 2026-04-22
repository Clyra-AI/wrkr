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

func (Detector) Detect(ctx context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	_ = ctx
	return agentframework.DetectManyWithOptions(scope, []agentframework.DetectorConfig{
		{
			DetectorID: detectorID,
			Framework:  "llamaindex",
			ConfigPath: ".wrkr/agents/llamaindex.yaml",
			Format:     "yaml",
		},
		{
			DetectorID: detectorID,
			Framework:  "llamaindex",
			ConfigPath: ".wrkr/agents/llamaindex.yml",
			Format:     "yaml",
		},
		{
			DetectorID: detectorID,
			Framework:  "llamaindex",
			ConfigPath: ".wrkr/agents/llamaindex.json",
			Format:     "json",
		},
		{
			DetectorID: detectorID,
			Framework:  "llamaindex",
			ConfigPath: ".wrkr/agents/llamaindex.toml",
			Format:     "toml",
		},
	}, options)
}
