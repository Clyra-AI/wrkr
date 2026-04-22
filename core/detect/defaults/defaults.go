package defaults

import (
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/a2a"
	"github.com/Clyra-AI/wrkr/core/detect/agentautogen"
	"github.com/Clyra-AI/wrkr/core/detect/agentcrewai"
	"github.com/Clyra-AI/wrkr/core/detect/agentcustom"
	"github.com/Clyra-AI/wrkr/core/detect/agentlangchain"
	"github.com/Clyra-AI/wrkr/core/detect/agentllamaindex"
	"github.com/Clyra-AI/wrkr/core/detect/agentmcpclient"
	"github.com/Clyra-AI/wrkr/core/detect/agentopenai"
	"github.com/Clyra-AI/wrkr/core/detect/ciagent"
	"github.com/Clyra-AI/wrkr/core/detect/claude"
	"github.com/Clyra-AI/wrkr/core/detect/codex"
	"github.com/Clyra-AI/wrkr/core/detect/compiledaction"
	"github.com/Clyra-AI/wrkr/core/detect/copilot"
	"github.com/Clyra-AI/wrkr/core/detect/cursor"
	"github.com/Clyra-AI/wrkr/core/detect/dependency"
	"github.com/Clyra-AI/wrkr/core/detect/extension"
	"github.com/Clyra-AI/wrkr/core/detect/gaitpolicy"
	"github.com/Clyra-AI/wrkr/core/detect/mcp"
	"github.com/Clyra-AI/wrkr/core/detect/mcpgateway"
	"github.com/Clyra-AI/wrkr/core/detect/nonhumanidentity"
	"github.com/Clyra-AI/wrkr/core/detect/promptchannel"
	"github.com/Clyra-AI/wrkr/core/detect/secrets"
	"github.com/Clyra-AI/wrkr/core/detect/skills"
	"github.com/Clyra-AI/wrkr/core/detect/webmcp"
	"github.com/Clyra-AI/wrkr/core/detect/workstation"
)

func Registry() (*detect.Registry, error) {
	return RegistryForMode("governance")
}

func RegistryForMode(mode string) (*detect.Registry, error) {
	registry := detect.NewRegistry()
	detectorList := detectorsForMode(mode)
	for _, detector := range detectorList {
		if err := registry.Register(detector); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func detectorsForMode(mode string) []detect.Detector {
	switch mode {
	case "quick":
		return []detect.Detector{
			claude.New(),
			cursor.New(),
			codex.New(),
			copilot.New(),
			mcp.New(),
			mcpgateway.New(),
			skills.New(),
			gaitpolicy.New(),
			secrets.New(),
			ciagent.New(),
		}
	default:
		return []detect.Detector{
			a2a.New(),
			agentlangchain.New(),
			agentcrewai.New(),
			agentopenai.New(),
			agentautogen.New(),
			agentllamaindex.New(),
			agentmcpclient.New(),
			agentcustom.New(),
			claude.New(),
			cursor.New(),
			codex.New(),
			copilot.New(),
			mcp.New(),
			workstation.New(),
			mcpgateway.New(),
			nonhumanidentity.New(),
			webmcp.New(),
			promptchannel.New(),
			skills.New(),
			gaitpolicy.New(),
			dependency.New(),
			extension.New(),
			secrets.New(),
			compiledaction.New(),
			ciagent.New(),
		}
	}
}
