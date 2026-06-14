package cli

import (
	"io"

	"github.com/Clyra-AI/wrkr/core/state"
)

func rejectIncompleteSavedState(stderr io.Writer, jsonOut bool, statePath string, snapshot state.Snapshot) (int, bool) {
	if err := state.IncompleteSourceError(statePath, snapshot); err != nil {
		return emitError(stderr, jsonOut, "invalid_input", err.Error(), exitInvalidInput), true
	}
	return exitSuccess, false
}
