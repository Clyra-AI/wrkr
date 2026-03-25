package workflowcap

import (
	"fmt"
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

type workflowDocument struct {
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
		Triggers: append([]string(nil), doc.On.Names...),
	}
	capabilityReasons := map[string]map[string]struct{}{}
	approvalSources := map[string]struct{}{}
	deploymentGates := map[string]struct{}{}
	proofRequirements := map[string]struct{}{}

	jobNames := make([]string, 0, len(doc.Jobs))
	for name := range doc.Jobs {
		jobNames = append(jobNames, name)
	}
	sort.Strings(jobNames)

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

		jobApprovalSource := ""
		jobDeploymentGate := ""
		jobHasDeliverySurface := false
		jobHasGovernanceSurface := false
		jobProofRequirements := map[string]struct{}{}
		if strings.TrimSpace(job.Environment.Name) != "" {
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

			if reason := mergeExecuteReason(step); reason != "" && (perms.allows("contents") || perms.allows("pull-requests")) {
				addCapabilityReason(capabilityReasons, "merge.execute", reason)
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
	if result.ApprovalSource != "" {
		evidence = append(evidence, model.Evidence{Key: "approval_source", Value: result.ApprovalSource})
	}
	if result.DeploymentGate != "" {
		evidence = append(evidence, model.Evidence{Key: "deployment_gate", Value: result.DeploymentGate})
	}
	if result.ProofRequirement != "" {
		evidence = append(evidence, model.Evidence{Key: "proof_requirement", Value: result.ProofRequirement})
	}
	result.Evidence = evidence
	return result, nil
}

func effectivePermissions(root, job permissionField) permissionField {
	if job.Mode != "" || len(job.Values) > 0 {
		return job
	}
	return root
}

func detectTool(step workflowStep) string {
	values := normalizedStepValues(step, nil)
	for _, value := range values {
		switch {
		case strings.Contains(value, "claude"):
			return "claude"
		case strings.Contains(value, "codex"):
			return "codex"
		case strings.Contains(value, "copilot"):
			return "copilot"
		case strings.Contains(value, "cursor"):
			return "cursor"
		case strings.Contains(value, "gait eval --script"):
			return "gait"
		}
	}
	return ""
}

func isHeadlessStep(step workflowStep) bool {
	for _, value := range normalizedStepValues(step, nil) {
		switch {
		case strings.Contains(value, "claude -p"),
			strings.Contains(value, "claude code -p"),
			strings.Contains(value, "codex --full-auto"),
			strings.Contains(value, "gait eval --script"):
			return true
		}
	}
	return false
}

func hasDangerousFlags(step workflowStep) bool {
	for _, value := range normalizedStepValues(step, nil) {
		switch {
		case strings.Contains(value, "--dangerouslyskippermissions"),
			strings.Contains(value, "--dangerously-skip-permissions"),
			strings.Contains(value, "--approval never"):
			return true
		}
	}
	return false
}

func stepHasSecretAccess(step workflowStep, jobEnv map[string]string) bool {
	values := normalizedStepValues(step, jobEnv)
	for _, value := range values {
		if strings.Contains(value, "secrets.") || strings.Contains(value, "${{ secrets.") {
			return true
		}
	}
	return false
}

func mergeExecuteReason(step workflowStep) string {
	for _, value := range normalizedStepValues(step, nil) {
		switch {
		case strings.Contains(value, "gh pr merge"):
			return "step.run:gh_pr_merge"
		case strings.Contains(value, "enable-pull-request-automerge"):
			return "step.uses:enable_pull_request_automerge"
		case strings.Contains(value, "automerge-action"):
			return "step.uses:automerge_action"
		}
	}
	return ""
}

func deployWriteReason(step workflowStep) string {
	for _, value := range normalizedStepValues(step, nil) {
		switch {
		case strings.Contains(value, "kubectl apply"):
			return "step.run:kubectl_apply"
		case strings.Contains(value, "helm upgrade"), strings.Contains(value, "helm install"):
			return "step.run:helm_release"
		case strings.Contains(value, "terraform apply"):
			return "step.run:terraform_apply"
		case strings.Contains(value, "terragrunt apply"):
			return "step.run:terragrunt_apply"
		case strings.Contains(value, "pulumi up"):
			return "step.run:pulumi_up"
		case strings.Contains(value, "serverless deploy"):
			return "step.run:serverless_deploy"
		case strings.Contains(value, "fly deploy"):
			return "step.run:fly_deploy"
		case strings.Contains(value, "vercel deploy --prod"):
			return "step.run:vercel_prod_deploy"
		case strings.Contains(value, "netlify deploy --prod"):
			return "step.run:netlify_prod_deploy"
		case strings.Contains(value, "aws ecs update-service"):
			return "step.run:aws_ecs_update_service"
		case strings.Contains(value, "gcloud run deploy"):
			return "step.run:gcloud_run_deploy"
		case strings.Contains(value, "azure/k8s-deploy"):
			return "step.uses:azure_k8s_deploy"
		case strings.Contains(value, "amazon-ecs-deploy-task-definition"):
			return "step.uses:amazon_ecs_deploy"
		case strings.Contains(value, "deploy-cloudrun"):
			return "step.uses:deploy_cloudrun"
		}
	}
	return ""
}

func dbWriteReason(step workflowStep) string {
	for _, value := range normalizedStepValues(step, nil) {
		switch {
		case strings.Contains(value, "alembic upgrade"):
			return "step.run:alembic_upgrade"
		case strings.Contains(value, "prisma migrate deploy"):
			return "step.run:prisma_migrate_deploy"
		case strings.Contains(value, "liquibase update"):
			return "step.run:liquibase_update"
		case strings.Contains(value, "flyway migrate"):
			return "step.run:flyway_migrate"
		case strings.Contains(value, "goose up"):
			return "step.run:goose_up"
		case strings.Contains(value, "dbmate up"):
			return "step.run:dbmate_up"
		case strings.Contains(value, "rails db:migrate"):
			return "step.run:rails_db_migrate"
		case strings.Contains(value, "knex migrate:latest"):
			return "step.run:knex_migrate_latest"
		case strings.Contains(value, "sqitch deploy"):
			return "step.run:sqitch_deploy"
		}
	}
	return ""
}

func iacWriteReason(step workflowStep) string {
	for _, value := range normalizedStepValues(step, nil) {
		switch {
		case strings.Contains(value, "terraform apply"):
			return "step.run:terraform_apply"
		case strings.Contains(value, "terragrunt apply"):
			return "step.run:terragrunt_apply"
		case strings.Contains(value, "pulumi up"):
			return "step.run:pulumi_up"
		case strings.Contains(value, "helm upgrade"), strings.Contains(value, "helm install"):
			return "step.run:helm_release"
		}
	}
	return ""
}

func manualApprovalSource(step workflowStep) string {
	for _, value := range normalizedStepValues(step, nil) {
		if strings.Contains(value, "manual-approval") {
			return "manual_approval_step"
		}
	}
	return ""
}

func proofRequirement(step workflowStep) string {
	for _, value := range normalizedStepValues(step, nil) {
		switch {
		case strings.Contains(value, "wrkr evidence"),
			strings.Contains(value, "wrkr verify"):
			return "evidence"
		case strings.Contains(value, "cosign attest"),
			strings.Contains(value, "attest-build-provenance"),
			strings.Contains(value, "slsa-github-generator"),
			strings.Contains(value, "gh attestation"),
			strings.Contains(value, "slsa-verifier"):
			return "attestation"
		}
	}
	return ""
}

func normalizedStepValues(step workflowStep, jobEnv map[string]string) []string {
	values := []string{
		strings.ToLower(strings.TrimSpace(step.Name)),
		strings.ToLower(strings.TrimSpace(step.Uses)),
		strings.ToLower(strings.TrimSpace(step.Run)),
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
