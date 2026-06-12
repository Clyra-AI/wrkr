package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

// wantsJSONOutput inspects raw args to decide whether errors should be emitted as JSON.
func wantsJSONOutput(args []string) bool {
	for _, arg := range args {
		if arg == "--json" {
			return true
		}
		if strings.HasPrefix(arg, "--json=") {
			value := strings.TrimPrefix(arg, "--json=")
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return true
			}
			return parsed
		}
	}
	return false
}

type jsonOutputSink struct {
	writeStdout bool
	stdout      io.Writer
	outputPath  string
}

func newJSONOutputSink(writeStdout bool, rawPath string, stdout io.Writer) (jsonOutputSink, error) {
	sink := jsonOutputSink{
		writeStdout: writeStdout,
		stdout:      stdout,
	}
	if strings.TrimSpace(rawPath) == "" {
		return sink, nil
	}

	path, err := resolveArtifactOutputPath(rawPath)
	if err != nil {
		return jsonOutputSink{}, err
	}
	sink.outputPath = path
	return sink, nil
}

func (s jsonOutputSink) enabled() bool {
	return s.writeStdout || strings.TrimSpace(s.outputPath) != ""
}

func (s jsonOutputSink) writePayload(payload any) error {
	if !s.enabled() {
		return nil
	}

	if s.writeStdout {
		if err := json.NewEncoder(s.stdout).Encode(payload); err != nil {
			return fmt.Errorf("write json payload stdout: %w", err)
		}
	}
	if strings.TrimSpace(s.outputPath) != "" {
		if err := atomicwrite.WriteFileFunc(s.outputPath, 0o600, func(w io.Writer) error {
			return json.NewEncoder(w).Encode(payload)
		}); err != nil {
			return fmt.Errorf("write json payload %s: %w", s.outputPath, err)
		}
	}
	return nil
}
