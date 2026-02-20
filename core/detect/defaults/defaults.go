package defaults

import (
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/ciagent"
	"github.com/Clyra-AI/wrkr/core/detect/claude"
	"github.com/Clyra-AI/wrkr/core/detect/codex"
	"github.com/Clyra-AI/wrkr/core/detect/compiledaction"
	"github.com/Clyra-AI/wrkr/core/detect/copilot"
	"github.com/Clyra-AI/wrkr/core/detect/cursor"
	"github.com/Clyra-AI/wrkr/core/detect/dependency"
	"github.com/Clyra-AI/wrkr/core/detect/gaitpolicy"
	"github.com/Clyra-AI/wrkr/core/detect/mcp"
	"github.com/Clyra-AI/wrkr/core/detect/secrets"
	"github.com/Clyra-AI/wrkr/core/detect/skills"
)

func Registry() (*detect.Registry, error) {
	registry := detect.NewRegistry()
	detectorList := []detect.Detector{
		claude.New(),
		cursor.New(),
		codex.New(),
		copilot.New(),
		mcp.New(),
		skills.New(),
		gaitpolicy.New(),
		dependency.New(),
		secrets.New(),
		compiledaction.New(),
		ciagent.New(),
	}
	for _, detector := range detectorList {
		if err := registry.Register(detector); err != nil {
			return nil, err
		}
	}
	return registry, nil
}
