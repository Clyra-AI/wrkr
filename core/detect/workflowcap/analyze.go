package workflowcap

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "workflowcap"

type Result struct {
	Capabilities     []string
	Evidence         []model.Evidence
	Tool             string
	WorkflowName     string
	JobNames         []string
	EnvironmentNames []string
	Headless         bool
	DangerousFlags   bool
	HasSecretAccess  bool
	HasApprovalGate  bool
	StepCount        int
	Triggers         []string
	ApprovalSource   string
	DeploymentGate   string
	ProofRequirement string
}

var (
	workflowSecretRefRE   = regexp.MustCompile(`\${{[^}\n]*\bsecrets\.([A-Za-z0-9_]+)\b[^}\n]*}}`)
	workflowGitHubTokenRE = regexp.MustCompile(`\${{\s*(?:github\.token|secrets\.GITHUB_TOKEN)\s*}}`)
)

type workflowDocument struct {
	Name        string                 `yaml:"name"`
	On          triggerField           `yaml:"on"`
	Permissions permissionField        `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Permissions permissionField   `yaml:"permissions"`
	Environment environmentField  `yaml:"environment"`
	Env         map[string]string `yaml:"env"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	If   string            `yaml:"if"`
	Env  map[string]string `yaml:"env"`
	With map[string]any    `yaml:"with"`
}

type permissionField struct {
	Mode   string
	Values map[string]string
}

func (p *permissionField) UnmarshalYAML(node *yaml.Node) error {
	p.Mode = ""
	p.Values = nil
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		var mode string
		if err := node.Decode(&mode); err != nil {
			return err
		}
		p.Mode = strings.ToLower(strings.TrimSpace(mode))
		return nil
	case yaml.MappingNode:
		decoded := map[string]string{}
		if err := node.Decode(&decoded); err != nil {
			return err
		}
		values := map[string]string{}
		for key, value := range decoded {
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.ToLower(strings.TrimSpace(value))
			if key == "" || value == "" {
				continue
			}
			values[key] = value
		}
		if len(values) > 0 {
			p.Values = values
		}
		return nil
	default:
		return fmt.Errorf("unsupported permissions shape")
	}
}

func (p permissionField) allows(scope string) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	switch p.Mode {
	case "write-all":
		return true
	case "read-all":
		return false
	}
	if len(p.Values) == 0 {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(p.Values[scope]))
	return value == "write"
}

type environmentField struct {
	Name string
}

func (e *environmentField) UnmarshalYAML(node *yaml.Node) error {
	e.Name = ""
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		e.Name = strings.TrimSpace(node.Value)
	case yaml.MappingNode:
		for idx := 0; idx+1 < len(node.Content); idx += 2 {
			if strings.EqualFold(strings.TrimSpace(node.Content[idx].Value), "name") {
				e.Name = strings.TrimSpace(node.Content[idx+1].Value)
				break
			}
		}
	}
	return nil
}

type triggerField struct {
	Names []string
}

func (t *triggerField) UnmarshalYAML(node *yaml.Node) error {
	t.Names = nil
	if node == nil {
		return nil
	}
	names := map[string]struct{}{}
	switch node.Kind {
	case yaml.ScalarNode:
		if name := strings.TrimSpace(node.Value); name != "" {
			names[name] = struct{}{}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if name := strings.TrimSpace(child.Value); name != "" {
				names[name] = struct{}{}
			}
		}
	case yaml.MappingNode:
		for idx := 0; idx+1 < len(node.Content); idx += 2 {
			if name := strings.TrimSpace(node.Content[idx].Value); name != "" {
				names[name] = struct{}{}
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	t.Names = make([]string, 0, len(names))
	for name := range names {
		t.Names = append(t.Names, name)
	}
	sort.Strings(t.Names)
	return nil
}

func Analyze(path string, payload []byte) (Result, *model.ParseError) {
	return AnalyzeInRoot("", path, payload)
}

func analyzeGitHubWorkflow(path string, payload []byte) (Result, *model.ParseError) {
	var doc workflowDocument
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return Result{}, &model.ParseError{
			Kind:     "parse_error",
			Format:   "yaml",
			Path:     strings.TrimSpace(path),
			Detector: detectorID,
			Message:  err.Error(),
		}
	}

	result := Result{
		WorkflowName: strings.TrimSpace(doc.Name),
		Triggers:     append([]string(nil), doc.On.Names...),
	}
	capabilityReasons := map[string]map[string]struct{}{}
	approvalSources := map[string]struct{}{}
	deploymentGates := map[string]struct{}{}
	proofRequirements := map[string]struct{}{}
	secretRefs := map[string]struct{}{}
	environmentNames := map[string]struct{}{}
	workflowTokenPermissions := map[string]struct{}{}
	authSurfaces := map[string]struct{}{}
	authorityBindings := map[string]struct{}{}
	hasBuiltinWorkflowToken := false

	jobNames := make([]string, 0, len(doc.Jobs))
	for name := range doc.Jobs {
		jobNames = append(jobNames, name)
	}
	sort.Strings(jobNames)
	result.JobNames = append([]string(nil), jobNames...)

	hasDeliverySurface := false
	for _, jobName := range jobNames {
		job := doc.Jobs[jobName]
		perms := effectivePermissions(doc.Permissions, job.Permissions)
		if perms.allows("contents") {
			addCapabilityReason(capabilityReasons, "repo.write", "permissions.contents=write")
		}
		if perms.allows("pull-requests") {
			addCapabilityReason(capabilityReasons, "pull_request.write", "permissions.pull-requests=write")
		}
		if perms.allows("id-token") {
			addCapabilityReason(capabilityReasons, "id-token.write", "permissions.id-token=write")
		}

		jobApprovalSource := ""
		jobDeploymentGate := ""
		jobHasDeliverySurface := false
		jobHasGovernanceSurface := false
		jobProofRequirements := map[string]struct{}{}
		if strings.TrimSpace(job.Environment.Name) != "" {
			environmentNames[strings.TrimSpace(job.Environment.Name)] = struct{}{}
			jobApprovalSource = "environment"
			jobDeploymentGate = "ambiguous"
		}

		for _, step := range job.Steps {
			result.StepCount++
			stepTool := detectTool(step)
			if result.Tool == "" {
				result.Tool = stepTool
			}
			if stepTool != "" {
				jobHasGovernanceSurface = true
			}
			if isHeadlessStep(step) {
				result.Headless = true
				jobHasGovernanceSurface = true
			}
			if hasDangerousFlags(step) {
				result.DangerousFlags = true
				jobHasGovernanceSurface = true
			}
			if stepHasSecretAccess(step, job.Env) {
				result.HasSecretAccess = true
			}
			refs, builtinToken := workflowCredentialRefs(step, job.Env)
			for _, ref := range refs {
				secretRefs[ref] = struct{}{}
			}
			for _, surface := range workflowAuthSurfaces(step, job.Env) {
				authSurfaces[surface] = struct{}{}
			}
			if builtinToken {
				hasBuiltinWorkflowToken = true
				result.HasSecretAccess = true
				for _, posture := range permissionPosture(perms) {
					workflowTokenPermissions[posture] = struct{}{}
				}
			}
			for _, binding := range workflowAuthorityBindings(step, strings.TrimSpace(job.Environment.Name)) {
				authorityBindings[binding] = struct{}{}
			}

			if reason := mergeExecuteReason(step); reason != "" && (perms.allows("contents") || perms.allows("pull-requests")) {
				addCapabilityReason(capabilityReasons, "merge.execute", reason)
				jobHasDeliverySurface = true
				hasDeliverySurface = true
			}
			if reason := releaseWriteReason(step); reason != "" {
				addCapabilityReason(capabilityReasons, "release.write", reason)
				jobHasDeliverySurface = true
				hasDeliverySurface = true
			}
			if reason := packagePublishReason(step); reason != "" {
				addCapabilityReason(capabilityReasons, "package.write", reason)
				jobHasDeliverySurface = true
				hasDeliverySurface = true
			}
			if reason := deployWriteReason(step); reason != "" {
				addCapabilityReason(capabilityReasons, "deploy.write", reason)
				jobHasDeliverySurface = true
				hasDeliverySurface = true
			}
			if reason := dbWriteReason(step); reason != "" {
				addCapabilityReason(capabilityReasons, "db.write", reason)
				jobHasDeliverySurface = true
				hasDeliverySurface = true
			}
			if reason := iacWriteReason(step); reason != "" {
				addCapabilityReason(capabilityReasons, "iac.write", reason)
				jobHasDeliverySurface = true
				hasDeliverySurface = true
			}

			if source := manualApprovalSource(step); source != "" {
				jobApprovalSource = source
				jobDeploymentGate = "approved"
				result.HasApprovalGate = true
			}
			if requirement := proofRequirement(step); requirement != "" {
				jobProofRequirements[requirement] = struct{}{}
			}
		}

		if jobHasDeliverySurface || jobHasGovernanceSurface {
			if jobApprovalSource == "" {
				if containsTrigger(result.Triggers, "workflow_dispatch") {
					jobApprovalSource = "workflow_dispatch"
				} else {
					jobApprovalSource = "missing"
				}
			}
			if jobHasDeliverySurface && jobDeploymentGate == "" {
				jobDeploymentGate = "open"
			}
			if len(jobProofRequirements) == 0 {
				proofRequirements["missing"] = struct{}{}
			} else {
				for requirement := range jobProofRequirements {
					proofRequirements[requirement] = struct{}{}
				}
			}
			if jobApprovalSource != "" {
				approvalSources[jobApprovalSource] = struct{}{}
			}
			if jobHasDeliverySurface && jobDeploymentGate != "" {
				deploymentGates[jobDeploymentGate] = struct{}{}
			}
		}
	}

	if hasDeliverySurface && len(proofRequirements) == 0 {
		proofRequirements["missing"] = struct{}{}
	}

	result.Capabilities = sortedKeys(capabilityReasons)
	result.EnvironmentNames = sortedSet(environmentNames)
	result.ApprovalSource = chooseApprovalSource(approvalSources)
	result.DeploymentGate = chooseDeploymentGate(deploymentGates)
	result.ProofRequirement = chooseProofRequirement(proofRequirements)
	result.HasApprovalGate = result.HasApprovalGate || result.DeploymentGate == "approved"

	evidence := make([]model.Evidence, 0, len(result.Capabilities)+5)
	if len(result.Capabilities) > 0 {
		evidence = append(evidence, model.Evidence{
			Key:   "workflow_capabilities",
			Value: strings.Join(result.Capabilities, ","),
		})
		for _, capability := range result.Capabilities {
			reasons := capabilityReasons[capability]
			evidence = append(evidence, model.Evidence{
				Key:   "workflow_capability." + capability,
				Value: strings.Join(sortedSet(reasons), ","),
			})
		}
	}
	if len(result.Triggers) > 0 {
		evidence = append(evidence, model.Evidence{
			Key:   "workflow_triggers",
			Value: strings.Join(result.Triggers, ","),
		})
	}
	if strings.TrimSpace(result.WorkflowName) != "" {
		evidence = append(evidence, model.Evidence{Key: "workflow_name", Value: result.WorkflowName})
	}
	if len(result.JobNames) > 0 {
		evidence = append(evidence, model.Evidence{Key: "workflow_jobs", Value: strings.Join(result.JobNames, ",")})
	}
	if len(result.EnvironmentNames) > 0 {
		evidence = append(evidence, model.Evidence{Key: "workflow_environment", Value: strings.Join(result.EnvironmentNames, ",")})
	}
	if result.ApprovalSource != "" {
		evidence = append(evidence, model.Evidence{Key: "approval_source", Value: result.ApprovalSource})
	}
	if result.DeploymentGate != "" {
		evidence = append(evidence, model.Evidence{Key: "deployment_gate", Value: result.DeploymentGate})
	}
	if result.ProofRequirement != "" {
		evidence = append(evidence, model.Evidence{Key: "proof_requirement", Value: result.ProofRequirement})
	}
	if targetClassHint := workflowTargetClassHint(result); targetClassHint != "" {
		evidence = append(evidence, model.Evidence{Key: "target_class_hint", Value: targetClassHint})
	}
	evidence = appendWorkflowSecretEvidence(evidence, secretRefs)
	if len(authSurfaces) > 0 {
		evidence = append(evidence, model.Evidence{Key: "auth_surfaces", Value: strings.Join(sortedSet(authSurfaces), ",")})
	}
	if hasBuiltinWorkflowToken {
		evidence = append(evidence, model.Evidence{Key: "workflow_builtin_token", Value: "github_token"})
		for _, posture := range sortedSet(workflowTokenPermissions) {
			evidence = append(evidence, model.Evidence{Key: "workflow_token_permission", Value: posture})
		}
	}
	for _, binding := range sortedSet(authorityBindings) {
		evidence = append(evidence, model.Evidence{Key: "authority_binding", Value: binding})
	}
	result.Evidence = appendDeliveryControlEvidence(path, string(payload), result, evidence)
	result.Evidence = appendPlatformEvidence(result.Evidence, "github_actions", "high")
	return result, nil
}

func workflowTargetClassHint(result Result) string {
	switch {
	case workflowEnvironmentSuggestsProduction(result.EnvironmentNames):
		return "production_impacting"
	case containsValue(result.Capabilities, "deploy.write"), containsValue(result.Capabilities, "release.write"), containsValue(result.Capabilities, "package.write"), containsValue(result.Capabilities, "iac.write"):
		return "release_adjacent"
	default:
		return ""
	}
}

func workflowEnvironmentSuggestsProduction(values []string) bool {
	for _, value := range values {
		lower := strings.ToLower(strings.TrimSpace(value))
		tokens := strings.FieldsFunc(lower, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < '0' || r > '9')
		})
		for _, token := range tokens {
			switch token {
			case "prod", "production", "live":
				return true
			}
		}
	}
	return false
}

func containsValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func effectivePermissions(root, job permissionField) permissionField {
	if job.Mode != "" || len(job.Values) > 0 {
		return job
	}
	return root
}

func detectTool(step workflowStep) string {
	return detectToolFromValues(normalizedStepValues(step, nil))
}

func isHeadlessStep(step workflowStep) bool {
	return isHeadlessValues(normalizedStepValues(step, nil))
}

func hasDangerousFlags(step workflowStep) bool {
	return hasDangerousFlagsValues(normalizedStepValues(step, nil))
}

func stepHasSecretAccess(step workflowStep, jobEnv map[string]string) bool {
	return hasSecretAccessValues(normalizedStepValues(step, jobEnv))
}

func mergeExecuteReason(step workflowStep) string {
	return mergeExecuteReasonValues(normalizedStepValues(step, nil))
}

func deployWriteReason(step workflowStep) string {
	return deployWriteReasonValues(normalizedStepValues(step, nil))
}

func releaseWriteReason(step workflowStep) string {
	return releaseWriteReasonValues(normalizedStepValues(step, nil))
}

func packagePublishReason(step workflowStep) string {
	return packagePublishReasonValues(normalizedStepValues(step, nil))
}

func dbWriteReason(step workflowStep) string {
	return dbWriteReasonValues(normalizedStepValues(step, nil))
}

func iacWriteReason(step workflowStep) string {
	return iacWriteReasonValues(normalizedStepValues(step, nil))
}

func manualApprovalSource(step workflowStep) string {
	return manualApprovalSourceValues(normalizedStepValues(step, nil))
}

func proofRequirement(step workflowStep) string {
	return proofRequirementValues(normalizedStepValues(step, nil))
}

func normalizedStepValues(step workflowStep, jobEnv map[string]string) []string {
	values := []string{
		strings.ToLower(strings.TrimSpace(step.Name)),
		strings.ToLower(strings.TrimSpace(step.Uses)),
		strings.ToLower(strings.TrimSpace(step.Run)),
		strings.ToLower(strings.TrimSpace(step.If)),
	}
	for _, env := range []map[string]string{jobEnv, step.Env} {
		for key, value := range env {
			values = append(values, strings.ToLower(strings.TrimSpace(key)))
			values = append(values, strings.ToLower(strings.TrimSpace(value)))
		}
	}
	values = append(values, normalizeDynamicValues(step.With)...)
	return values
}

func normalizeDynamicValues(values map[string]any) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values)*2)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, strings.ToLower(strings.TrimSpace(key)))
		out = append(out, strings.ToLower(strings.TrimSpace(fmt.Sprint(values[key]))))
	}
	return out
}

func workflowCredentialRefs(step workflowStep, jobEnv map[string]string) ([]string, bool) {
	refs := map[string]struct{}{}
	builtinToken := false
	for _, env := range []map[string]string{jobEnv, step.Env} {
		for key, value := range env {
			collectWorkflowCredentialRef(refs, key, value)
			if workflowUsesGitHubToken(key, value) {
				builtinToken = true
			}
		}
	}
	for key, value := range step.With {
		text := strings.TrimSpace(fmt.Sprint(value))
		collectWorkflowCredentialRef(refs, key, text)
		if workflowUsesGitHubToken(key, text) {
			builtinToken = true
		}
	}
	for _, value := range []string{step.Run, step.If} {
		collectWorkflowCredentialRef(refs, "", value)
		if workflowUsesGitHubToken("", value) {
			builtinToken = true
		}
	}
	out := make([]string, 0, len(refs))
	for ref := range refs {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out, builtinToken
}

func collectWorkflowCredentialRef(target map[string]struct{}, key, value string) {
	for _, match := range workflowSecretRefRE.FindAllStringSubmatch(value, -1) {
		if len(match) > 1 {
			target[strings.TrimSpace(match[1])] = struct{}{}
		}
	}
}

func workflowUsesGitHubToken(key, value string) bool {
	valueLower := strings.ToLower(strings.TrimSpace(value))
	return workflowGitHubTokenRE.MatchString(value) ||
		strings.Contains(valueLower, "github.token")
}

func sensitiveCredentialName(key string) bool {
	tokens := credentialNameTokens(key)
	if len(tokens) == 0 {
		return false
	}
	if containsCredentialSequence(tokens, "persist", "credentials") {
		return false
	}
	for _, token := range tokens {
		switch token {
		case "token", "secret", "secrets", "credential", "credentials", "password", "passwd", "pat", "webhook":
			return true
		}
	}
	if !containsCredentialToken(tokens, "key") {
		return false
	}
	for _, token := range tokens {
		switch token {
		case "api", "access", "admin", "app", "cloud", "deploy", "private", "secret", "signing", "ssh":
			return true
		}
	}
	return false
}

func credentialKindForReference(ref string) string {
	tokens := credentialNameTokens(ref)
	switch {
	case len(tokens) == 2 && containsCredentialSequence(tokens, "github", "token"):
		return "github_workflow_token"
	case containsCredentialToken(tokens, "github") && containsCredentialToken(tokens, "app") && containsCredentialToken(tokens, "key"):
		return "github_app_key"
	case (containsCredentialToken(tokens, "deploy") || containsCredentialToken(tokens, "ssh")) && containsCredentialToken(tokens, "key"):
		return "deploy_key"
	case containsAnyCredentialToken(tokens, "aws", "azure", "gcp", "cloud") && containsAnyCredentialToken(tokens, "admin", "owner", "root"):
		return "cloud_admin_key"
	case containsAnyCredentialToken(tokens, "aws", "azure", "gcp", "cloud") && containsAnyCredentialToken(tokens, "access", "credential", "credentials", "service"):
		return "cloud_access_key"
	case containsCredentialToken(tokens, "pat") || containsCredentialSequence(tokens, "personal", "access", "token"):
		return "github_pat"
	case containsCredentialToken(tokens, "oauth"):
		return "delegated_oauth"
	case containsCredentialToken(tokens, "oidc") || containsCredentialSequence(tokens, "workload", "identity"):
		return "oidc_workload_identity"
	case sensitiveCredentialName(ref):
		return "static_secret"
	default:
		return ""
	}
}

func appendWorkflowSecretEvidence(evidence []model.Evidence, secretRefs map[string]struct{}) []model.Evidence {
	for _, ref := range sortedSet(secretRefs) {
		evidence = append(evidence, model.Evidence{Key: "workflow_secret_refs", Value: ref})
		if kind := credentialKindForReference(ref); kind != "" {
			evidence = append(evidence, model.Evidence{Key: "workflow_credential_kind", Value: ref + "|" + kind})
			continue
		}
		evidence = append(evidence, model.Evidence{Key: "workflow_noncredential_secret_refs", Value: ref})
	}
	return evidence
}

func credentialNameTokens(value string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	return strings.FieldsFunc(value, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

func containsAnyCredentialToken(tokens []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if containsCredentialToken(tokens, candidate) {
			return true
		}
	}
	return false
}

func containsCredentialToken(tokens []string, candidate string) bool {
	for _, token := range tokens {
		if token == candidate {
			return true
		}
	}
	return false
}

func containsCredentialSequence(tokens []string, sequence ...string) bool {
	if len(sequence) == 0 || len(tokens) < len(sequence) {
		return false
	}
	for start := 0; start <= len(tokens)-len(sequence); start++ {
		matched := true
		for offset := range sequence {
			if tokens[start+offset] != sequence[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func workflowAuthSurfaces(step workflowStep, jobEnv map[string]string) []string {
	return workflowAuthSurfacesFromValues(normalizedStepValues(step, jobEnv), workflowCredentialRefsOnly(step, jobEnv), nil)
}

func workflowCredentialRefsOnly(step workflowStep, jobEnv map[string]string) []string {
	refs, _ := workflowCredentialRefs(step, jobEnv)
	return refs
}

func workflowAuthorityBindings(step workflowStep, environment string) []string {
	return workflowAuthorityBindingsFromValues(normalizedStepValues(step, nil), environment, nil)
}

func dedupeSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, item := range in {
		if strings.TrimSpace(item) == "" {
			continue
		}
		set[strings.TrimSpace(item)] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func permissionPosture(perms permissionField) []string {
	if perms.Mode == "write-all" {
		return []string{"write-all"}
	}
	if len(perms.Values) == 0 {
		return []string{"unspecified"}
	}
	out := make([]string, 0, len(perms.Values))
	for key, value := range perms.Values {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, strings.ToLower(strings.TrimSpace(key))+"="+strings.ToLower(strings.TrimSpace(value)))
	}
	sort.Strings(out)
	return out
}

func addCapabilityReason(target map[string]map[string]struct{}, capability, reason string) {
	capability = strings.TrimSpace(capability)
	reason = strings.TrimSpace(reason)
	if capability == "" || reason == "" {
		return
	}
	if target[capability] == nil {
		target[capability] = map[string]struct{}{}
	}
	target[capability][reason] = struct{}{}
}

func sortedKeys(values map[string]map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortedSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func chooseApprovalSource(values map[string]struct{}) string {
	if len(values) == 0 {
		return "missing"
	}
	if len(values) == 1 {
		return sortedSet(values)[0]
	}
	return "ambiguous"
}

func chooseDeploymentGate(values map[string]struct{}) string {
	if len(values) == 0 {
		return "missing"
	}
	if len(values) == 1 {
		return sortedSet(values)[0]
	}
	return "ambiguous"
}

func chooseProofRequirement(values map[string]struct{}) string {
	if len(values) == 0 {
		return "missing"
	}
	if _, ok := values["missing"]; ok {
		return "missing"
	}
	if _, ok := values["attestation"]; ok {
		return "attestation"
	}
	if _, ok := values["evidence"]; ok {
		return "evidence"
	}
	return sortedSet(values)[0]
}

func containsTrigger(triggers []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, trigger := range triggers {
		if strings.TrimSpace(trigger) == needle {
			return true
		}
	}
	return false
}
