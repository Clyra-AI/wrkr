package workflowcap

import (
	"sort"
	"strings"
	"unicode"

	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const maxJenkinsBytes = 2 << 20

type groovyString struct {
	value   string
	line    int
	dynamic bool
}

func analyzeJenkinsWorkflow(path string, payload []byte) (Result, *model.ParseError) {
	if len(payload) > maxJenkinsBytes {
		return Result{}, &model.ParseError{Kind: "size_limit", Format: "groovy", Path: path, Detector: detectorID, Message: "Jenkins source exceeds the static analysis limit"}
	}
	clean := stripGroovyComments(string(payload))
	lower := strings.ToLower(clean)
	codeOnly := stripGroovyStringLiterals(clean)
	values := []string{lower}
	result := Result{WorkflowName: path, StepCount: countJenkinsSteps(lower)}
	result.Tool = detectToolFromValues(values)
	result.Headless = isHeadlessValues(values)
	result.DangerousFlags = hasDangerousFlagsValues(values)
	result.HasApprovalGate = containsGroovyIdentifier(codeOnly, "input")
	result.HasSecretAccess = containsGroovyIdentifier(codeOnly, "withCredentials") || containsGroovyIdentifier(codeOnly, "credentials") || containsGroovyIdentifier(codeOnly, "sshagent")

	capabilityReasons := map[string]string{}
	for capability, reason := range map[string]string{
		"merge.execute": mergeExecuteReasonValues(values), "deploy.write": deployWriteReasonValues(values),
		"release.write": releaseWriteReasonValues(values), "package.write": packagePublishReasonValues(values),
		"db.write": dbWriteReasonValues(values), "iac.write": iacWriteReasonValues(values),
	} {
		if reason != "" {
			capabilityReasons[capability] = reason
		}
	}
	for capability := range capabilityReasons {
		result.Capabilities = append(result.Capabilities, capability)
	}
	sort.Strings(result.Capabilities)

	credentialRefs := groovyValues(
		extractNamedGroovyStrings(clean, "credentialsId"),
		extractGroovyCallStrings(clean, "credentials"),
		extractGroovyCallStrings(clean, "sshagent"),
	)
	evidence := []model.Evidence{{Key: "workflow_name", Value: path}}
	if len(result.Capabilities) > 0 {
		evidence = append(evidence, model.Evidence{Key: "workflow_capabilities", Value: strings.Join(result.Capabilities, ",")})
		for _, capability := range result.Capabilities {
			evidence = append(evidence, model.Evidence{Key: "workflow_capability." + capability, Value: capabilityReasons[capability]})
		}
	}
	if len(credentialRefs) > 0 {
		evidence = append(evidence,
			model.Evidence{Key: "workflow_secret_refs", Value: strings.Join(credentialRefs, ",")},
			model.Evidence{Key: "credential_scope", Value: "workflow"},
		)
	}
	if result.HasApprovalGate {
		result.ApprovalSource = "jenkins_input"
		result.DeploymentGate = "approved"
		evidence = append(evidence, model.Evidence{Key: "approval_source", Value: result.ApprovalSource})
	}
	libraries := append(extractGroovyAnnotationStrings(clean, "Library"), extractGroovyCallStrings(clean, "library")...)
	libraries = append(libraries, extractGroovyBareStrings(clean, "library")...)
	for _, library := range dedupeGroovyStrings(libraries) {
		alias := strings.Split(strings.TrimSpace(library.value), "@")[0]
		state := "unresolved_external"
		if library.dynamic || alias == "" {
			state = "unsupported_dynamic"
		}
		evidence = append(evidence, model.Evidence{Key: "execution_relationship", Value: strings.Join([]string{"jenkins_shared_library", path, alias, state, lineReceipt(library.line)}, "|")})
	}
	loads := append(extractGroovyCallStrings(clean, "load"), extractGroovyBareStrings(clean, "load")...)
	for _, loaded := range dedupeGroovyStrings(loads) {
		state := "resolved_local"
		if loaded.dynamic || strings.TrimSpace(loaded.value) == "" {
			state = "unsupported_dynamic"
		}
		evidence = append(evidence, model.Evidence{Key: "execution_relationship", Value: strings.Join([]string{"local_script", path, loaded.value, state, lineReceipt(loaded.line)}, "|")})
	}
	result.Evidence = appendPlatformEvidence(evidence, "jenkins", "medium")
	return result, nil
}

func stripGroovyStringLiterals(payload string) string {
	var out strings.Builder
	out.Grow(len(payload))
	runes := []rune(payload)
	quote := rune(0)
	triple := false
	escaped := false
	for index := 0; index < len(runes); index++ {
		current := runes[index]
		if quote == 0 {
			if current == '\'' || current == '"' {
				quote = current
				triple = index+2 < len(runes) && runes[index+1] == current && runes[index+2] == current
				out.WriteRune(' ')
				if triple {
					out.WriteString("  ")
					index += 2
				}
				continue
			}
			out.WriteRune(current)
			continue
		}
		if triple && current == quote && index+2 < len(runes) && runes[index+1] == quote && runes[index+2] == quote {
			out.WriteString("   ")
			index += 2
			quote = 0
			triple = false
			continue
		}
		if current == '\n' {
			out.WriteRune(current)
		} else {
			out.WriteRune(' ')
		}
		if escaped {
			escaped = false
		} else if current == '\\' {
			escaped = true
		} else if !triple && current == quote {
			quote = 0
		}
	}
	return out.String()
}

func stripGroovyComments(payload string) string {
	var out strings.Builder
	out.Grow(len(payload))
	inLineComment, inBlockComment := false, false
	quote := rune(0)
	escaped := false
	runes := []rune(payload)
	for i := 0; i < len(runes); i++ {
		current := runes[i]
		next := rune(0)
		if i+1 < len(runes) {
			next = runes[i+1]
		}
		if inLineComment {
			if current == '\n' {
				inLineComment = false
				out.WriteRune(current)
			} else {
				out.WriteRune(' ')
			}
			continue
		}
		if inBlockComment {
			if current == '*' && next == '/' {
				out.WriteString("  ")
				i++
				inBlockComment = false
			} else if current == '\n' {
				out.WriteRune(current)
			} else {
				out.WriteRune(' ')
			}
			continue
		}
		if quote != 0 {
			out.WriteRune(current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == quote {
				quote = 0
			}
			continue
		}
		if current == '/' && next == '/' {
			out.WriteString("  ")
			i++
			inLineComment = true
			continue
		}
		if current == '/' && next == '*' {
			out.WriteString("  ")
			i++
			inBlockComment = true
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
		}
		out.WriteRune(current)
	}
	return out.String()
}

func extractNamedGroovyStrings(payload, name string) []groovyString {
	return extractGroovyStrings(payload, name, ':', false)
}

func extractGroovyCallStrings(payload, name string) []groovyString {
	return extractGroovyStrings(payload, name, '(', true)
}

func extractGroovyAnnotationStrings(payload, name string) []groovyString {
	out := extractGroovyStrings(payload, "@"+name, '(', true)
	runes := []rune(payload)
	target := "@" + name
	for start := 0; start < len(runes); {
		index := indexIdentifier(runes, start, target)
		if index < 0 {
			break
		}
		cursor := index + len([]rune(target))
		for cursor < len(runes) && unicode.IsSpace(runes[cursor]) {
			cursor++
		}
		if cursor >= len(runes) || runes[cursor] != '(' {
			start = index + 1
			continue
		}
		cursor++
		for cursor < len(runes) && unicode.IsSpace(runes[cursor]) {
			cursor++
		}
		if cursor >= len(runes) || runes[cursor] != '[' {
			start = index + 1
			continue
		}
		cursor++
		for cursor < len(runes) && runes[cursor] != ']' {
			for cursor < len(runes) && (unicode.IsSpace(runes[cursor]) || runes[cursor] == ',') {
				cursor++
			}
			value, next, ok := readGroovyString(runes, cursor)
			if !ok {
				cursor++
				continue
			}
			value.line = 1 + strings.Count(string(runes[:cursor]), "\n")
			out = append(out, value)
			cursor = next
		}
		start = cursor + 1
	}
	return dedupeGroovyStrings(out)
}

func extractGroovyBareStrings(payload, name string) []groovyString {
	return extractGroovyStrings(payload, name, ' ', false)
}

func extractGroovyStrings(payload, name string, separator rune, call bool) []groovyString {
	runes := []rune(payload)
	out := []groovyString{}
	for i := 0; i < len(runes); {
		index := indexIdentifier(runes, i, name)
		if index < 0 {
			break
		}
		cursor := index + len([]rune(name))
		whitespaceStart := cursor
		for cursor < len(runes) && unicode.IsSpace(runes[cursor]) {
			cursor++
		}
		if separator == ' ' {
			if cursor == whitespaceStart {
				i = index + 1
				continue
			}
		} else if cursor >= len(runes) || runes[cursor] != separator {
			i = index + 1
			continue
		}
		if separator != ' ' {
			cursor++
		}
		if call && separator == '(' {
			for cursor < len(runes) && unicode.IsSpace(runes[cursor]) {
				cursor++
			}
		}
		value, next, ok := readGroovyString(runes, cursor)
		if ok {
			value.line = 1 + strings.Count(string(runes[:index]), "\n")
			out = append(out, value)
			i = next
			continue
		}
		i = index + 1
	}
	return dedupeGroovyStrings(out)
}

func readGroovyString(runes []rune, start int) (groovyString, int, bool) {
	for start < len(runes) && (unicode.IsSpace(runes[start]) || runes[start] == '[') {
		start++
	}
	if start >= len(runes) || (runes[start] != '\'' && runes[start] != '"') {
		return groovyString{}, start, false
	}
	quote := runes[start]
	var value strings.Builder
	escaped := false
	for i := start + 1; i < len(runes); i++ {
		if escaped {
			value.WriteRune(runes[i])
			escaped = false
			continue
		}
		if runes[i] == '\\' {
			escaped = true
			continue
		}
		if runes[i] == quote {
			text := strings.TrimSpace(value.String())
			return groovyString{value: text, dynamic: strings.Contains(text, "$"), line: 1}, i + 1, true
		}
		value.WriteRune(runes[i])
	}
	return groovyString{}, len(runes), false
}

func indexIdentifier(runes []rune, start int, name string) int {
	target := []rune(name)
	for i := start; i+len(target) <= len(runes); i++ {
		if string(runes[i:i+len(target)]) != name {
			continue
		}
		if i > 0 && isGroovyIdentifierRune(runes[i-1]) {
			continue
		}
		end := i + len(target)
		if end < len(runes) && isGroovyIdentifierRune(runes[end]) {
			continue
		}
		return i
	}
	return -1
}

func isGroovyIdentifierRune(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsDigit(value) || value == '_'
}

func containsGroovyIdentifier(payload, name string) bool {
	return indexIdentifier([]rune(payload), 0, name) >= 0
}

func groovyValues(groups ...[]groovyString) []string {
	set := map[string]struct{}{}
	for _, group := range groups {
		for _, item := range group {
			if !item.dynamic && strings.TrimSpace(item.value) != "" {
				set[strings.TrimSpace(item.value)] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func dedupeGroovyStrings(values []groovyString) []groovyString {
	seen := map[string]struct{}{}
	out := make([]groovyString, 0, len(values))
	for _, value := range values {
		key := value.value + "|" + lineReceipt(value.line)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		return out[i].value < out[j].value
	})
	return out
}

func lineReceipt(line int) string {
	if line < 1 {
		line = 1
	}
	return "line:" + strconvItoa(line)
}

func strconvItoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := [20]byte{}
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

func countJenkinsSteps(payload string) int {
	count := 0
	for _, token := range []string{"sh", "bat", "powershell", "checkout", "input", "withcredentials", "sshagent"} {
		if containsGroovyIdentifier(payload, token) {
			count++
		}
	}
	return count
}

func analyzeCompositeAction(root, path string, payload []byte) (Result, *model.ParseError) {
	var doc struct {
		Name string `yaml:"name"`
		Runs struct {
			Using string         `yaml:"using"`
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return Result{}, &model.ParseError{Kind: "parse_error", Format: "yaml", Path: path, Detector: detectorID, Message: err.Error()}
	}
	using := strings.ToLower(strings.TrimSpace(doc.Runs.Using))
	if using == "" {
		return Result{}, &model.ParseError{Kind: "parse_error", Format: "yaml", Path: path, Detector: detectorID, Message: "action runs.using is required"}
	}
	if using != "composite" {
		if using != "docker" && !strings.HasPrefix(using, "node") {
			return Result{}, &model.ParseError{Kind: "unsupported_format", Format: "yaml", Path: path, Detector: detectorID, Message: "unsupported action runtime " + using}
		}
		result := Result{WorkflowName: strings.TrimSpace(doc.Name)}
		result.Evidence = appendPlatformEvidence([]model.Evidence{
			{Key: "action_runtime", Value: using},
			{Key: "execution_model", Value: "opaque_implementation"},
			{Key: "shared_source_role", Value: "github_action"},
		}, "github_actions", "high")
		return result, nil
	}
	result := Result{WorkflowName: strings.TrimSpace(doc.Name), StepCount: len(doc.Runs.Steps)}
	values := []string{}
	executionRelationships := map[string]struct{}{}
	for _, step := range doc.Runs.Steps {
		values = append(values, normalizedStepValues(step, nil)...)
		if strings.HasPrefix(strings.TrimSpace(step.Uses), "./") {
			executionRelationships[githubExecutionRelationship(root, path, step.Uses, "github_composite_action")] = struct{}{}
		}
	}
	result.Tool = detectToolFromValues(values)
	result.Headless = isHeadlessValues(values)
	result.DangerousFlags = hasDangerousFlagsValues(values)
	result.HasSecretAccess = hasSecretAccessValues(values)
	capabilityReasons := map[string]string{
		"merge.execute": mergeExecuteReasonValues(values), "deploy.write": deployWriteReasonValues(values),
		"release.write": releaseWriteReasonValues(values), "package.write": packagePublishReasonValues(values),
		"db.write": dbWriteReasonValues(values), "iac.write": iacWriteReasonValues(values),
	}
	evidence := []model.Evidence{{Key: "shared_source_role", Value: "github_composite_action"}}
	for capability, reason := range capabilityReasons {
		if reason == "" {
			delete(capabilityReasons, capability)
			continue
		}
		result.Capabilities = append(result.Capabilities, capability)
	}
	sort.Strings(result.Capabilities)
	if len(result.Capabilities) > 0 {
		evidence = append(evidence, model.Evidence{Key: "workflow_capabilities", Value: strings.Join(result.Capabilities, ",")})
		for _, capability := range result.Capabilities {
			evidence = append(evidence, model.Evidence{Key: "workflow_capability." + capability, Value: capabilityReasons[capability]})
		}
	}
	for _, relationship := range sortedSet(executionRelationships) {
		evidence = append(evidence, model.Evidence{Key: "execution_relationship", Value: relationship})
	}
	result.Evidence = appendPlatformEvidence(evidence, "github_actions", "high")
	return result, nil
}
