package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	stdoutMode  jsonStdoutMode
	capability  jsonOutputCapabilities
}

func newJSONOutputSink(writeStdout bool, rawPath string, stdout io.Writer, stdoutMode jsonStdoutMode) (jsonOutputSink, error) {
	sink := jsonOutputSink{
		writeStdout: writeStdout,
		stdout:      stdout,
		stdoutMode:  stdoutMode,
		capability:  detectJSONOutputCapabilities(stdout),
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

func (s jsonOutputSink) usesCompactStdout() bool {
	return s.writeStdout && s.stdoutMode != jsonStdoutModeFull && s.capability.Interactive
}

func (s jsonOutputSink) writePayload(payload any) error {
	return s.writePayloads(payload, payload)
}

func (s jsonOutputSink) writePayloads(stdoutPayload any, filePayload any) error {
	if !s.enabled() {
		return nil
	}

	if s.writeStdout {
		payload := filePayload
		if s.usesCompactStdout() && stdoutPayload != nil {
			payload = stdoutPayload
		}
		if err := json.NewEncoder(s.stdout).Encode(payload); err != nil {
			return fmt.Errorf("write json payload stdout: %w", err)
		}
	}
	if strings.TrimSpace(s.outputPath) != "" {
		if err := atomicwrite.WriteFileFunc(s.outputPath, 0o600, func(w io.Writer) error {
			return json.NewEncoder(w).Encode(filePayload)
		}); err != nil {
			return fmt.Errorf("write json payload %s: %w", s.outputPath, err)
		}
	}
	return nil
}

type jsonStdoutMode string

const (
	jsonStdoutModeAuto jsonStdoutMode = "auto"
	jsonStdoutModeFull jsonStdoutMode = "full"
)

type jsonOutputCapabilities struct {
	Interactive bool
}

type jsonOutputCapabilityProvider interface {
	JSONOutputCapabilities() jsonOutputCapabilities
}

func parseJSONStdoutMode(raw string) (jsonStdoutMode, error) {
	switch mode := jsonStdoutMode(strings.TrimSpace(raw)); mode {
	case "", jsonStdoutModeAuto:
		return jsonStdoutModeAuto, nil
	case jsonStdoutModeFull:
		return jsonStdoutModeFull, nil
	default:
		return "", fmt.Errorf("--json-stdout must be one of auto or full")
	}
}

func detectJSONOutputCapabilities(stdout io.Writer) jsonOutputCapabilities {
	if provider, ok := stdout.(jsonOutputCapabilityProvider); ok {
		return provider.JSONOutputCapabilities()
	}
	file, ok := stdout.(*os.File)
	if !ok {
		return jsonOutputCapabilities{}
	}
	info, err := file.Stat()
	if err != nil {
		return jsonOutputCapabilities{}
	}
	return jsonOutputCapabilities{Interactive: info.Mode()&os.ModeCharDevice != 0}
}
