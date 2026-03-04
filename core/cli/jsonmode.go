package cli

import (
	"strconv"
	"strings"
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
