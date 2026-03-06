package agentmcpclient

import (
	"context"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/agentframework"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "agentmcpclient"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	return agentframework.DetectMany(scope, []agentframework.DetectorConfig{
		{
			DetectorID: detectorID,
			Framework:  "mcp_client",
			ConfigPath: ".wrkr/agents/mcp-client.yaml",
			Format:     "yaml",
		},
		{
			DetectorID: detectorID,
			Framework:  "mcp_client",
			ConfigPath: ".wrkr/agents/mcp-client.yml",
			Format:     "yaml",
		},
		{
			DetectorID: detectorID,
			Framework:  "mcp_client",
			ConfigPath: ".wrkr/agents/mcp-client.json",
			Format:     "json",
		},
		{
			DetectorID: detectorID,
			Framework:  "mcp_client",
			ConfigPath: ".wrkr/agents/mcp-client.toml",
			Format:     "toml",
		},
	})
}
