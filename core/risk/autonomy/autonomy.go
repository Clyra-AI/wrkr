package autonomy

import "strings"

const (
	LevelInteractive  = "interactive"
	LevelCopilot      = "copilot"
	LevelHeadlessGate = "headless_gated"
	LevelHeadlessAuto = "headless_auto"
)

// Signals are extracted from CI/headless execution context.
type Signals struct {
	Tool            string
	Headless        bool
	HasApprovalGate bool
	HasSecretAccess bool
	DangerousFlags  bool
}

func Classify(signals Signals) string {
	tool := strings.ToLower(strings.TrimSpace(signals.Tool))
	if strings.Contains(tool, "copilot") {
		return LevelCopilot
	}
	if !signals.Headless {
		return LevelInteractive
	}
	if signals.HasApprovalGate {
		return LevelHeadlessGate
	}
	return LevelHeadlessAuto
}

func IsCritical(signals Signals) bool {
	return Classify(signals) == LevelHeadlessAuto && signals.HasSecretAccess && signals.DangerousFlags
}
