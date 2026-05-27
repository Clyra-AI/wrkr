package workflowcap

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/workflowloc"
	"gopkg.in/yaml.v3"
)

var (
	shellVariableRefRE = regexp.MustCompile(`\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)`)
	azureVariableRefRE = regexp.MustCompile(`\$\(([A-Za-z0-9_.-]+)\)`)
)

func AnalyzeInRoot(root, path string, payload []byte) (Result, *model.ParseError) {
	switch {
	case workflowloc.IsGitLabEntryPipeline(path):
		return analyzeGitLabWorkflow(root, path, payload)
	case workflowloc.IsAzurePipelinePath(path):
		return analyzeAzureWorkflow(root, path, payload)
	default:
		return analyzeGitHubWorkflow(path, payload)
	}
}

func appendPlatformEvidence(in []model.Evidence, platform string, confidence string) []model.Evidence {
	out := append([]model.Evidence(nil), in...)
	if strings.TrimSpace(platform) != "" {
		out = append(out, model.Evidence{Key: "ci_platform", Value: strings.TrimSpace(platform)})
	}
	if strings.TrimSpace(confidence) != "" {
		out = append(out, model.Evidence{Key: "parser_confidence", Value: strings.TrimSpace(confidence)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key == out[j].Key {
			return out[i].Value < out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func detectToolFromValues(values []string) string {
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

func isHeadlessValues(values []string) bool {
	for _, value := range values {
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

func hasDangerousFlagsValues(values []string) bool {
	for _, value := range values {
		switch {
		case strings.Contains(value, "--dangerouslyskippermissions"),
			strings.Contains(value, "--dangerously-skip-permissions"),
			strings.Contains(value, "--approval never"):
			return true
		}
	}
	return false
}

func hasSecretAccessValues(values []string) bool {
	for _, value := range values {
		if strings.Contains(value, "secrets.") ||
			strings.Contains(value, "${{ secrets.") ||
			strings.Contains(value, "github.token") ||
			strings.Contains(value, "$(") {
			return true
		}
	}
	return false
}

func mergeExecuteReasonValues(values []string) string {
	for _, value := range values {
		switch {
		case strings.Contains(value, "gh pr merge"):
			return "step.run:gh_pr_merge"
		case strings.Contains(value, "glab mr merge"):
			return "job.script:glab_mr_merge"
		case strings.Contains(value, "enable-pull-request-automerge"):
			return "step.uses:enable_pull_request_automerge"
		case strings.Contains(value, "automerge-action"):
			return "step.uses:automerge_action"
		}
	}
	return ""
}

func deployWriteReasonValues(values []string) string {
	for _, value := range values {
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
		case strings.Contains(value, "az webapp deploy"), strings.Contains(value, "az deployment group create"), strings.Contains(value, "az deployment sub create"):
			return "step.run:azure_deploy"
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

func releaseWriteReasonValues(values []string) string {
	for _, value := range values {
		switch {
		case strings.Contains(value, "goreleaser release"):
			return "step.run:goreleaser_release"
		case strings.Contains(value, "gh release create"):
			return "step.run:gh_release_create"
		case strings.Contains(value, "glab release create"):
			return "job.script:glab_release_create"
		case strings.Contains(value, "softprops/action-gh-release"):
			return "step.uses:action_gh_release"
		case strings.Contains(value, "actions/create-release"):
			return "step.uses:create_release"
		}
	}
	return ""
}

func packagePublishReasonValues(values []string) string {
	for _, value := range values {
		switch {
		case strings.Contains(value, "npm publish"):
			return "step.run:npm_publish"
		case strings.Contains(value, "pnpm publish"):
			return "step.run:pnpm_publish"
		case strings.Contains(value, "yarn npm publish"):
			return "step.run:yarn_npm_publish"
		case strings.Contains(value, "twine upload"):
			return "step.run:twine_upload"
		case strings.Contains(value, "docker push"):
			return "step.run:docker_push"
		case strings.Contains(value, "docker/build-push-action"):
			return "step.uses:docker_build_push_action"
		case strings.Contains(value, "pypa/gh-action-pypi-publish"):
			return "step.uses:pypi_publish"
		}
	}
	return ""
}

func dbWriteReasonValues(values []string) string {
	for _, value := range values {
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

func iacWriteReasonValues(values []string) string {
	for _, value := range values {
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

func manualApprovalSourceValues(values []string) string {
	for _, value := range values {
		if strings.Contains(value, "manual-approval") {
			return "manual_approval_step"
		}
	}
	return ""
}

func proofRequirementValues(values []string) string {
	for _, value := range values {
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

func workflowAuthSurfacesFromValues(values []string, refs []string, explicit []string) []string {
	out := map[string]struct{}{}
	for _, value := range values {
		switch {
		case strings.Contains(value, "aws-actions/configure-aws-credentials"), strings.Contains(value, "role-to-assume"), strings.Contains(value, "assume_role"):
			out["aws_oidc"] = struct{}{}
		case strings.Contains(value, "azure/login"), strings.Contains(value, "federatedcredential"), strings.Contains(value, "service connection"):
			out["azure_federated_credential"] = struct{}{}
		case strings.Contains(value, "google-github-actions/auth"), strings.Contains(value, "workload_identity_provider"), strings.Contains(value, "service_account"):
			out["gcp_workload_identity"] = struct{}{}
		case strings.Contains(value, "kubectl"), strings.Contains(value, "helm"):
			out["kubernetes_rbac"] = struct{}{}
		}
	}
	for _, ref := range append(append([]string(nil), refs...), explicit...) {
		if strings.TrimSpace(ref) != "" {
			out[strings.TrimSpace(ref)] = struct{}{}
		}
	}
	return sortedSet(out)
}

func workflowAuthorityBindingsFromValues(values []string, environment string, explicit []string) []string {
	production := workflowEnvironmentSuggestsProduction([]string{environment})
	out := append([]string(nil), explicit...)
	add := func(kind, provider, subject, targetSystem, resource, scope, access string) {
		out = append(out, strings.Join([]string{
			kind,
			provider,
			subject,
			targetSystem,
			resource,
			scope,
			access,
			environment,
			strconv.FormatBool(production),
			"high",
		}, "|"))
	}
	for _, value := range values {
		switch {
		case strings.Contains(value, "aws-actions/configure-aws-credentials"), strings.Contains(value, "role-to-assume"), strings.Contains(value, "assume_role"):
			add("workload_identity", "aws", "workflow_aws_oidc", "aws", "aws_role", "cloud_or_infra_access", "write")
		case strings.Contains(value, "azure/login"):
			add("workload_identity", "azure", "workflow_azure_federation", "azure", "azure_federated_credential", "cloud_or_infra_access", "write")
		case strings.Contains(value, "google-github-actions/auth"), strings.Contains(value, "workload_identity_provider"):
			add("workload_identity", "gcp", "workflow_gcp_workload_identity", "gcp", "gcp_workload_identity", "cloud_or_infra_access", "write")
		case strings.Contains(value, "kubectl apply"), strings.Contains(value, "azure/k8s-deploy"), strings.Contains(value, "helm upgrade"), strings.Contains(value, "helm install"):
			add("deployment_path", "kubernetes", "workflow_kubernetes_deploy", "kubernetes", "cluster_apply", "deploy_write", "write")
		case strings.Contains(value, "terraform apply"), strings.Contains(value, "terragrunt apply"):
			add("deployment_path", "terraform", "workflow_terraform_apply", "terraform", "terraform_apply", "infrastructure_apply", "write")
		case strings.Contains(value, "pulumi up"):
			add("deployment_path", "pulumi", "workflow_pulumi_up", "pulumi", "pulumi_up", "infrastructure_apply", "write")
		case strings.Contains(value, "gcloud run deploy"):
			add("deployment_path", "gcp", "workflow_gcloud_run_deploy", "gcp", "cloud_run", "deploy_write", "write")
		case strings.Contains(value, "aws ecs update-service"), strings.Contains(value, "amazon-ecs-deploy-task-definition"):
			add("deployment_path", "aws", "workflow_ecs_deploy", "aws", "ecs_service", "deploy_write", "write")
		case strings.Contains(value, "vercel deploy --prod"):
			add("service_connection", "vercel", "workflow_vercel_token", "deployment_platform", "vercel", "deploy_write", "write")
		case strings.Contains(value, "netlify deploy --prod"):
			add("service_connection", "netlify", "workflow_netlify_token", "deployment_platform", "netlify", "deploy_write", "write")
		}
	}
	sort.Strings(out)
	return dedupeSlice(out)
}

func extractShellVariableRefs(values ...string) []string {
	refs := map[string]struct{}{}
	for _, value := range values {
		for _, match := range shellVariableRefRE.FindAllStringSubmatch(value, -1) {
			if len(match) > 1 {
				name := strings.TrimSpace(match[1])
				if name != "" {
					refs[name] = struct{}{}
				}
			}
		}
		for _, match := range azureVariableRefRE.FindAllStringSubmatch(value, -1) {
			if len(match) > 1 {
				name := strings.TrimSpace(match[1])
				if name != "" {
					refs[name] = struct{}{}
				}
			}
		}
	}
	return sortedSet(refs)
}

type jobObservation struct {
	name              string
	environment       string
	values            []string
	secretRefs        []string
	authSurfaces      []string
	authorityBindings []string
	manualStrong      bool
	manualDeclared    bool
	ambiguousApproval bool
	stepCount         int
}

type workflowObservation struct {
	platform         string
	workflowName     string
	triggers         []string
	jobNames         []string
	environments     []string
	jobs             []jobObservation
	resolutionKey    string
	resolutionStatus string
}

func analyzeObservation(obs workflowObservation) Result {
	result := Result{
		WorkflowName:     strings.TrimSpace(obs.workflowName),
		Triggers:         dedupeSlice(obs.triggers),
		JobNames:         dedupeSlice(obs.jobNames),
		EnvironmentNames: dedupeSlice(obs.environments),
	}

	capabilityReasons := map[string]map[string]struct{}{}
	approvalSources := map[string]struct{}{}
	deploymentGates := map[string]struct{}{}
	proofRequirements := map[string]struct{}{}
	secretRefs := map[string]struct{}{}
	authSurfaces := map[string]struct{}{}
	authorityBindings := map[string]struct{}{}
	hasDeliverySurface := false
	partialResolution := strings.TrimSpace(obs.resolutionStatus) == "partial"

	for _, job := range obs.jobs {
		result.StepCount += job.stepCount
		jobTool := detectToolFromValues(job.values)
		jobHeadless := isHeadlessValues(job.values)
		jobDangerous := hasDangerousFlagsValues(job.values)
		jobSecretAccess := hasSecretAccessValues(job.values) || len(job.secretRefs) > 0
		if result.Tool == "" {
			result.Tool = jobTool
		}
		if jobHeadless {
			result.Headless = true
		}
		if jobDangerous {
			result.DangerousFlags = true
		}
		if jobSecretAccess {
			result.HasSecretAccess = true
		}
		for _, ref := range job.secretRefs {
			secretRefs[ref] = struct{}{}
		}
		for _, surface := range job.authSurfaces {
			authSurfaces[surface] = struct{}{}
		}
		for _, binding := range job.authorityBindings {
			authorityBindings[binding] = struct{}{}
		}

		jobHasDeliverySurface := false
		jobHasGovernanceSurface := jobTool != "" || jobHeadless || jobDangerous || job.manualDeclared || jobSecretAccess
		if reason := mergeExecuteReasonValues(job.values); reason != "" {
			addCapabilityReason(capabilityReasons, "merge.execute", reason)
			jobHasDeliverySurface = true
			hasDeliverySurface = true
		}
		if reason := releaseWriteReasonValues(job.values); reason != "" {
			addCapabilityReason(capabilityReasons, "release.write", reason)
			jobHasDeliverySurface = true
			hasDeliverySurface = true
		}
		if reason := packagePublishReasonValues(job.values); reason != "" {
			addCapabilityReason(capabilityReasons, "package.write", reason)
			jobHasDeliverySurface = true
			hasDeliverySurface = true
		}
		if reason := deployWriteReasonValues(job.values); reason != "" {
			addCapabilityReason(capabilityReasons, "deploy.write", reason)
			jobHasDeliverySurface = true
			hasDeliverySurface = true
		}
		if reason := dbWriteReasonValues(job.values); reason != "" {
			addCapabilityReason(capabilityReasons, "db.write", reason)
			jobHasDeliverySurface = true
			hasDeliverySurface = true
		}
		if reason := iacWriteReasonValues(job.values); reason != "" {
			addCapabilityReason(capabilityReasons, "iac.write", reason)
			jobHasDeliverySurface = true
			hasDeliverySurface = true
		}

		jobApprovalSource := ""
		jobDeploymentGate := ""
		switch {
		case job.manualStrong:
			jobApprovalSource = "manual_job"
			jobDeploymentGate = "approved"
			result.HasApprovalGate = true
		case job.manualDeclared || job.ambiguousApproval || partialResolution:
			jobApprovalSource = "ambiguous"
			jobDeploymentGate = "ambiguous"
		}

		if jobHasDeliverySurface || jobHasGovernanceSurface {
			if jobHasDeliverySurface && jobDeploymentGate == "" {
				jobDeploymentGate = "open"
			}
			if requirement := proofRequirementValues(job.values); requirement != "" {
				proofRequirements[requirement] = struct{}{}
			} else if jobHasDeliverySurface {
				proofRequirements["missing"] = struct{}{}
			}
			if jobApprovalSource == "" && (jobHasDeliverySurface || jobHasGovernanceSurface) {
				jobApprovalSource = "missing"
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

	evidence := make([]model.Evidence, 0, len(result.Capabilities)+12)
	if len(result.Capabilities) > 0 {
		evidence = append(evidence, model.Evidence{Key: "workflow_capabilities", Value: strings.Join(result.Capabilities, ",")})
		for _, capability := range result.Capabilities {
			evidence = append(evidence, model.Evidence{
				Key:   "workflow_capability." + capability,
				Value: strings.Join(sortedSet(capabilityReasons[capability]), ","),
			})
		}
	}
	if len(result.Triggers) > 0 {
		evidence = append(evidence, model.Evidence{Key: "workflow_triggers", Value: strings.Join(result.Triggers, ",")})
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
	if strings.TrimSpace(obs.resolutionKey) != "" && strings.TrimSpace(obs.resolutionStatus) != "" {
		evidence = append(evidence, model.Evidence{Key: obs.resolutionKey, Value: strings.TrimSpace(obs.resolutionStatus)})
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
	for _, ref := range sortedSet(secretRefs) {
		evidence = append(evidence, model.Evidence{Key: "workflow_secret_refs", Value: ref})
	}
	if len(authSurfaces) > 0 {
		evidence = append(evidence, model.Evidence{Key: "auth_surfaces", Value: strings.Join(sortedSet(authSurfaces), ",")})
	}
	for _, binding := range sortedSet(authorityBindings) {
		evidence = append(evidence, model.Evidence{Key: "authority_binding", Value: binding})
	}
	result.Evidence = appendPlatformEvidence(evidence, obs.platform, "high")
	return result
}

type stringListField []string

func (s *stringListField) UnmarshalYAML(node *yaml.Node) error {
	*s = nil
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		value := strings.TrimSpace(node.Value)
		if value != "" {
			*s = []string{value}
		}
		return nil
	case yaml.SequenceNode:
		values := make([]string, 0, len(node.Content))
		for _, child := range node.Content {
			value := strings.TrimSpace(child.Value)
			if value != "" {
				values = append(values, value)
			}
		}
		*s = values
		return nil
	default:
		return fmt.Errorf("unsupported string list shape")
	}
}

type gitlabDocument struct {
	Name         string                 `yaml:"name"`
	Stages       stringListField        `yaml:"stages"`
	Variables    map[string]any         `yaml:"variables"`
	Include      yaml.Node              `yaml:"include"`
	Workflow     yaml.Node              `yaml:"workflow"`
	Default      gitlabDefaults         `yaml:"default"`
	BeforeScript stringListField        `yaml:"before_script"`
	AfterScript  stringListField        `yaml:"after_script"`
	Image        any                    `yaml:"image"`
	Services     []any                  `yaml:"services"`
	Raw          map[string]*yaml.Node  `yaml:",inline"`
}

type gitlabDefaults struct {
	BeforeScript stringListField `yaml:"before_script"`
	AfterScript  stringListField `yaml:"after_script"`
	Image        any             `yaml:"image"`
	Services     []any           `yaml:"services"`
}

type gitlabJob struct {
	Stage        string            `yaml:"stage"`
	Script       stringListField   `yaml:"script"`
	BeforeScript stringListField   `yaml:"before_script"`
	AfterScript  stringListField   `yaml:"after_script"`
	Variables    map[string]any    `yaml:"variables"`
	Environment  environmentField  `yaml:"environment"`
	When         string            `yaml:"when"`
	Rules        []gitlabRule      `yaml:"rules"`
	Only         any               `yaml:"only"`
	Except       any               `yaml:"except"`
	Image        any               `yaml:"image"`
	Services     []any             `yaml:"services"`
	Needs        []any             `yaml:"needs"`
	Dependencies []any             `yaml:"dependencies"`
	Artifacts    map[string]any    `yaml:"artifacts"`
	Release      map[string]any    `yaml:"release"`
}

type gitlabRule struct {
	When string `yaml:"when"`
	If   string `yaml:"if"`
}

func analyzeGitLabWorkflow(root, path string, payload []byte) (Result, *model.ParseError) {
	obs := workflowObservation{
		platform:      "gitlab_ci",
		workflowName:  strings.TrimSpace(filepath.Base(path)),
		resolutionKey: "include_resolution_status",
	}
	loadErr := loadGitLabDocument(root, path, payload, map[string]struct{}{}, &obs)
	if strings.TrimSpace(obs.resolutionStatus) == "" {
		obs.resolutionStatus = "not_present"
	}
	return analyzeObservation(obs), loadErr
}

func loadGitLabDocument(root, path string, payload []byte, stack map[string]struct{}, obs *workflowObservation) *model.ParseError {
	normalizedPath := workflowloc.Normalize(path)
	if _, ok := stack[normalizedPath]; ok {
		obs.resolutionStatus = "partial"
		return &model.ParseError{Kind: "schema_validation_error", Format: "yaml", Path: path, Detector: detectorID, Message: "cyclic local include"}
	}
	stack[normalizedPath] = struct{}{}
	defer delete(stack, normalizedPath)

	var doc gitlabDocument
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return &model.ParseError{Kind: "parse_error", Format: "yaml", Path: path, Detector: detectorID, Message: err.Error()}
	}
	if strings.TrimSpace(doc.Name) != "" {
		obs.workflowName = strings.TrimSpace(doc.Name)
	}
	obs.triggers = append(obs.triggers, gitlabTriggerHints(doc.Workflow)...)
	var firstErr *model.ParseError

	if len(doc.Include.Content) > 0 {
		if obs.resolutionStatus == "" || obs.resolutionStatus == "not_present" {
			obs.resolutionStatus = "resolved"
		}
		for _, includeRef := range gitlabIncludeRefs(&doc.Include) {
			if includeRef.kind != "local" {
				obs.resolutionStatus = "partial"
				if firstErr == nil {
					firstErr = &model.ParseError{Kind: "schema_validation_error", Format: "yaml", Path: path, Detector: detectorID, Message: "unsupported remote include"}
				}
				continue
			}
			if strings.TrimSpace(root) == "" {
				obs.resolutionStatus = "partial"
				if firstErr == nil {
					firstErr = &model.ParseError{Kind: "schema_validation_error", Format: "yaml", Path: path, Detector: detectorID, Message: "local include requires scan root"}
				}
				continue
			}
			rel := normalizeGitLabLocalPath(includeRef.path)
			childPayload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
			if parseErr != nil {
				obs.resolutionStatus = "partial"
				parseErr.Path = path
				if parseErr.Message == "" {
					parseErr.Message = "failed to resolve local include"
				}
				if firstErr == nil {
					firstErr = parseErr
				}
				continue
			}
			if childErr := loadGitLabDocument(root, rel, childPayload, stack, obs); childErr != nil {
				obs.resolutionStatus = "partial"
				childErr.Path = path
				if firstErr == nil {
					firstErr = childErr
				}
			}
		}
	}

	rootNode, err := yamlDocumentNode(payload)
	if err != nil {
		return &model.ParseError{Kind: "parse_error", Format: "yaml", Path: path, Detector: detectorID, Message: err.Error()}
	}
	for key, value := range mappingChildren(rootNode) {
		if isGitLabReservedKey(key) {
			continue
		}
		var job gitlabJob
		if decodeErr := value.Decode(&job); decodeErr != nil {
			obs.resolutionStatus = "partial"
			if firstErr == nil {
				firstErr = &model.ParseError{Kind: "parse_error", Format: "yaml", Path: path, Detector: detectorID, Message: decodeErr.Error()}
			}
			continue
		}
		jobObs := observeGitLabJob(key, doc, job)
		obs.jobNames = append(obs.jobNames, jobObs.name)
		if strings.TrimSpace(jobObs.environment) != "" {
			obs.environments = append(obs.environments, jobObs.environment)
		}
		obs.jobs = append(obs.jobs, jobObs)
	}
	return firstErr
}

func observeGitLabJob(name string, doc gitlabDocument, job gitlabJob) jobObservation {
	values := []string{strings.ToLower(strings.TrimSpace(name)), strings.ToLower(strings.TrimSpace(job.Stage))}
	values = append(values, normalizeStringList(doc.BeforeScript)...)
	values = append(values, normalizeStringList(job.BeforeScript)...)
	values = append(values, normalizeStringList(job.Script)...)
	values = append(values, normalizeStringList(job.AfterScript)...)
	values = append(values, normalizeStringList(doc.AfterScript)...)
	values = append(values, normalizeDynamicValues(job.Release)...)
	values = append(values, normalizeDynamicValues(job.Artifacts)...)
	values = append(values, normalizeStringSlice(job.Services)...)
	values = append(values, normalizeDynamicValue(job.Image)...)
	values = append(values, normalizeDynamicValue(doc.Image)...)
	values = append(values, normalizeStringSlice(job.Dependencies)...)
	values = append(values, normalizeStringSlice(job.Needs)...)
	values = append(values, strings.ToLower(strings.TrimSpace(job.When)))
	for _, rule := range job.Rules {
		values = append(values, strings.ToLower(strings.TrimSpace(rule.When)))
		values = append(values, strings.ToLower(strings.TrimSpace(rule.If)))
	}
	for _, key := range sortedMapKeys(job.Variables) {
		values = append(values, strings.ToLower(strings.TrimSpace(key)))
		values = append(values, extractShellVariableRefs(fmt.Sprint(job.Variables[key]))...)
	}

	secretRefs := map[string]struct{}{}
	for _, ref := range extractShellVariableRefs(strings.Join(normalizeStringList(job.Script), "\n"), strings.Join(normalizeStringList(job.BeforeScript), "\n"), strings.Join(normalizeStringList(job.AfterScript), "\n")) {
		if sensitiveCredentialName(ref) {
			secretRefs[ref] = struct{}{}
		}
	}
	for _, key := range sortedMapKeys(job.Variables) {
		if sensitiveCredentialName(key) {
			secretRefs[key] = struct{}{}
		}
	}
	manualDeclared := strings.EqualFold(strings.TrimSpace(job.When), "manual")
	manualStrong := manualDeclared
	ambiguousApproval := false
	for _, rule := range job.Rules {
		if strings.EqualFold(strings.TrimSpace(rule.When), "manual") {
			manualDeclared = true
			if strings.TrimSpace(rule.If) == "" {
				manualStrong = true
			} else {
				ambiguousApproval = true
			}
		}
	}
	authSurfaces := workflowAuthSurfacesFromValues(values, sortedSet(secretRefs), nil)
	bindings := workflowAuthorityBindingsFromValues(values, job.Environment.Name, nil)
	return jobObservation{
		name:              strings.TrimSpace(name),
		environment:       strings.TrimSpace(job.Environment.Name),
		values:            dedupeSlice(values),
		secretRefs:        sortedSet(secretRefs),
		authSurfaces:      authSurfaces,
		authorityBindings: bindings,
		manualStrong:      manualStrong,
		manualDeclared:    manualDeclared,
		ambiguousApproval: ambiguousApproval,
		stepCount:         len(job.Script) + len(job.BeforeScript) + len(job.AfterScript),
	}
}

type gitlabIncludeRef struct {
	kind string
	path string
}

func gitlabIncludeRefs(node *yaml.Node) []gitlabIncludeRef {
	if node == nil || len(node.Content) == 0 {
		return nil
	}
	work := node
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		work = node.Content[0]
	}
	out := []gitlabIncludeRef{}
	add := func(kind, path string) {
		out = append(out, gitlabIncludeRef{kind: strings.TrimSpace(kind), path: strings.TrimSpace(path)})
	}
	switch work.Kind {
	case yaml.ScalarNode:
		add("local", work.Value)
	case yaml.SequenceNode:
		for _, child := range work.Content {
			out = append(out, gitlabIncludeRefs(child)...)
		}
	case yaml.MappingNode:
		mapping := mappingChildren(work)
		switch {
		case strings.TrimSpace(mappingValue(mapping, "local")) != "":
			add("local", mappingValue(mapping, "local"))
		case strings.TrimSpace(mappingValue(mapping, "file")) != "" && strings.TrimSpace(mappingValue(mapping, "project")) == "":
			add("local", mappingValue(mapping, "file"))
		default:
			add("remote", firstNonEmptyString(mappingValue(mapping, "remote"), mappingValue(mapping, "project"), mappingValue(mapping, "template"), mappingValue(mapping, "component"), "remote"))
		}
	}
	return out
}

func gitlabTriggerHints(node yaml.Node) []string {
	work := &node
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		work = node.Content[0]
	}
	if work == nil || work.Kind == 0 {
		return nil
	}
	triggers := map[string]struct{}{}
	switch work.Kind {
	case yaml.MappingNode:
		for key, value := range mappingChildren(work) {
			if strings.EqualFold(key, "rules") {
				for _, item := range value.Content {
					for childKey, childValue := range mappingChildren(item) {
						if strings.EqualFold(childKey, "if") && strings.TrimSpace(childValue.Value) != "" {
							triggers["conditional"] = struct{}{}
						}
						if strings.EqualFold(childKey, "when") && strings.EqualFold(strings.TrimSpace(childValue.Value), "manual") {
							triggers["manual"] = struct{}{}
						}
					}
				}
			}
		}
	}
	if len(triggers) == 0 {
		triggers["push"] = struct{}{}
	}
	return sortedSet(triggers)
}

func isGitLabReservedKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "name", "stages", "variables", "include", "workflow", "default", "before_script", "after_script", "image", "services", "cache", "pages":
		return true
	default:
		return false
	}
}

func normalizeGitLabLocalPath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "./")
	return filepath.ToSlash(filepath.Clean(path))
}

type azureDocument struct {
	Name      string            `yaml:"name"`
	Trigger   triggerField      `yaml:"trigger"`
	PR        triggerField      `yaml:"pr"`
	Variables yaml.Node         `yaml:"variables"`
	Extends   azureTemplateRef  `yaml:"extends"`
	Stages    []azureStage      `yaml:"stages"`
	Jobs      []azureJob        `yaml:"jobs"`
	Steps     []azureStep       `yaml:"steps"`
}

type azureTemplateRef struct {
	Template string `yaml:"template"`
}

type azureStage struct {
	Stage     string           `yaml:"stage"`
	Template  string           `yaml:"template"`
	Jobs      []azureJob       `yaml:"jobs"`
	Variables yaml.Node        `yaml:"variables"`
}

type azureJob struct {
	Job         string          `yaml:"job"`
	Deployment  string          `yaml:"deployment"`
	Template    string          `yaml:"template"`
	Environment environmentField `yaml:"environment"`
	Steps       []azureStep     `yaml:"steps"`
	Strategy    azureStrategy   `yaml:"strategy"`
	Variables   yaml.Node       `yaml:"variables"`
}

type azureStrategy struct {
	RunOnce struct {
		Deploy struct {
			Steps []azureStep `yaml:"steps"`
		} `yaml:"deploy"`
	} `yaml:"runOnce"`
}

type azureStep struct {
	DisplayName string            `yaml:"displayName"`
	Script      string            `yaml:"script"`
	Bash        string            `yaml:"bash"`
	Pwsh        string            `yaml:"pwsh"`
	Cmd         string            `yaml:"cmd"`
	Task        string            `yaml:"task"`
	Template    string            `yaml:"template"`
	Inputs      map[string]any    `yaml:"inputs"`
	Env         map[string]string `yaml:"env"`
}

func analyzeAzureWorkflow(root, path string, payload []byte) (Result, *model.ParseError) {
	obs := workflowObservation{
		platform:      "azure_devops",
		workflowName:  strings.TrimSpace(filepath.Base(path)),
		resolutionKey: "template_resolution_status",
	}
	loadErr := loadAzureDocument(root, path, payload, map[string]struct{}{}, &obs)
	if strings.TrimSpace(obs.resolutionStatus) == "" {
		obs.resolutionStatus = "not_present"
	}
	return analyzeObservation(obs), loadErr
}

func loadAzureDocument(root, path string, payload []byte, stack map[string]struct{}, obs *workflowObservation) *model.ParseError {
	normalizedPath := workflowloc.Normalize(path)
	if _, ok := stack[normalizedPath]; ok {
		obs.resolutionStatus = "partial"
		return &model.ParseError{Kind: "schema_validation_error", Format: "yaml", Path: path, Detector: detectorID, Message: "cyclic local template"}
	}
	stack[normalizedPath] = struct{}{}
	defer delete(stack, normalizedPath)

	var doc azureDocument
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return &model.ParseError{Kind: "parse_error", Format: "yaml", Path: path, Detector: detectorID, Message: err.Error()}
	}
	if strings.TrimSpace(doc.Name) != "" {
		obs.workflowName = strings.TrimSpace(doc.Name)
	}
	obs.triggers = append(obs.triggers, doc.Trigger.Names...)
	if len(doc.PR.Names) > 0 {
		for _, trigger := range doc.PR.Names {
			if strings.TrimSpace(trigger) != "" {
				obs.triggers = append(obs.triggers, "pull_request")
			}
		}
	}
	var firstErr *model.ParseError

	templateRefs := collectAzureTemplateRefs(doc)
	if len(templateRefs) > 0 {
		if obs.resolutionStatus == "" || obs.resolutionStatus == "not_present" {
			obs.resolutionStatus = "resolved"
		}
		for _, ref := range templateRefs {
			if strings.Contains(ref, "@") || strings.Contains(ref, "${{") || strings.Contains(ref, "$(") {
				obs.resolutionStatus = "partial"
				if firstErr == nil {
					firstErr = &model.ParseError{Kind: "schema_validation_error", Format: "yaml", Path: path, Detector: detectorID, Message: "unsupported remote template"}
				}
				continue
			}
			if strings.TrimSpace(root) == "" {
				obs.resolutionStatus = "partial"
				if firstErr == nil {
					firstErr = &model.ParseError{Kind: "schema_validation_error", Format: "yaml", Path: path, Detector: detectorID, Message: "local template requires scan root"}
				}
				continue
			}
			rel := normalizeAzureTemplatePath(path, ref)
			childPayload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
			if parseErr != nil {
				obs.resolutionStatus = "partial"
				parseErr.Path = path
				if firstErr == nil {
					firstErr = parseErr
				}
				continue
			}
			if childErr := loadAzureDocument(root, rel, childPayload, stack, obs); childErr != nil {
				obs.resolutionStatus = "partial"
				childErr.Path = path
				if firstErr == nil {
					firstErr = childErr
				}
			}
		}
	}

	variableNames, variableGroups := extractAzureVariables(&doc.Variables)
	_ = variableNames
	jobs := observeAzureJobs(doc, variableGroups)
	for _, job := range jobs {
		obs.jobNames = append(obs.jobNames, job.name)
		if strings.TrimSpace(job.environment) != "" {
			obs.environments = append(obs.environments, job.environment)
		}
		obs.jobs = append(obs.jobs, job)
	}
	return firstErr
}

func observeAzureJobs(doc azureDocument, variableGroups []string) []jobObservation {
	out := []jobObservation{}
	if len(doc.Jobs) > 0 {
		for _, job := range doc.Jobs {
			out = append(out, observeAzureJob(job, variableGroups)...)
		}
	}
	for _, stage := range doc.Stages {
		stageVars, stageGroups := extractAzureVariables(&stage.Variables)
		_ = stageVars
		groups := dedupeSlice(append(append([]string(nil), variableGroups...), stageGroups...))
		for _, job := range stage.Jobs {
			out = append(out, observeAzureJob(job, groups)...)
		}
	}
	if len(doc.Steps) > 0 {
		out = append(out, newAzureJobObservation("pipeline", "", doc.Steps, variableGroups, false))
	}
	return out
}

func observeAzureJob(job azureJob, variableGroups []string) []jobObservation {
	jobName := firstNonEmptyString(job.Deployment, job.Job, "job")
	steps := append([]azureStep(nil), job.Steps...)
	if len(job.Strategy.RunOnce.Deploy.Steps) > 0 {
		steps = append(steps, job.Strategy.RunOnce.Deploy.Steps...)
	}
	jobVariableNames, jobGroups := extractAzureVariables(&job.Variables)
	_ = jobVariableNames
	groups := dedupeSlice(append(append([]string(nil), variableGroups...), jobGroups...))
	return []jobObservation{newAzureJobObservation(jobName, job.Environment.Name, steps, groups, strings.TrimSpace(job.Environment.Name) != "")}
}

func newAzureJobObservation(name, environment string, steps []azureStep, variableGroups []string, ambiguousApproval bool) jobObservation {
	values := []string{strings.ToLower(strings.TrimSpace(name)), strings.ToLower(strings.TrimSpace(environment))}
	secretRefs := map[string]struct{}{}
	serviceConnections := []string{}
	for _, group := range variableGroups {
		values = append(values, strings.ToLower(strings.TrimSpace(group)))
	}
	for _, step := range steps {
		values = append(values, strings.ToLower(strings.TrimSpace(step.DisplayName)))
		values = append(values, strings.ToLower(strings.TrimSpace(step.Script)))
		values = append(values, strings.ToLower(strings.TrimSpace(step.Bash)))
		values = append(values, strings.ToLower(strings.TrimSpace(step.Pwsh)))
		values = append(values, strings.ToLower(strings.TrimSpace(step.Cmd)))
		values = append(values, strings.ToLower(strings.TrimSpace(step.Task)))
		values = append(values, normalizeDynamicValues(step.Inputs)...)
		for key, value := range step.Env {
			values = append(values, strings.ToLower(strings.TrimSpace(key)))
			values = append(values, strings.ToLower(strings.TrimSpace(value)))
			if sensitiveCredentialName(key) {
				secretRefs[strings.TrimSpace(key)] = struct{}{}
			}
			for _, ref := range extractShellVariableRefs(value) {
				if sensitiveCredentialName(ref) {
					secretRefs[ref] = struct{}{}
				}
			}
		}
		for _, ref := range extractShellVariableRefs(step.Script, step.Bash, step.Pwsh, step.Cmd, fmt.Sprint(step.Inputs)) {
			if sensitiveCredentialName(ref) {
				secretRefs[ref] = struct{}{}
			}
		}
		for key, value := range step.Inputs {
			lowerKey := strings.ToLower(strings.TrimSpace(key))
			if strings.Contains(lowerKey, "azuresubscription") ||
				strings.Contains(lowerKey, "connectedservice") ||
				strings.Contains(lowerKey, "serviceconnection") {
				serviceConnections = append(serviceConnections, strings.TrimSpace(fmt.Sprint(value)))
			}
		}
	}
	explicitBindings := []string{}
	production := workflowEnvironmentSuggestsProduction([]string{environment})
	for _, connection := range dedupeSlice(serviceConnections) {
		if strings.TrimSpace(connection) == "" {
			continue
		}
		explicitBindings = append(explicitBindings, strings.Join([]string{
			"service_connection",
			"azure",
			strings.TrimSpace(connection),
			"azure",
			"service_connection",
			"cloud_or_infra_access",
			"write",
			environment,
			strconv.FormatBool(production),
			"medium",
		}, "|"))
	}
	authSurfaces := workflowAuthSurfacesFromValues(values, sortedSet(secretRefs), serviceConnections)
	return jobObservation{
		name:              strings.TrimSpace(name),
		environment:       strings.TrimSpace(environment),
		values:            dedupeSlice(values),
		secretRefs:        sortedSet(secretRefs),
		authSurfaces:      authSurfaces,
		authorityBindings: workflowAuthorityBindingsFromValues(values, environment, explicitBindings),
		manualDeclared:    false,
		manualStrong:      false,
		ambiguousApproval: ambiguousApproval,
		stepCount:         len(steps),
	}
}

func collectAzureTemplateRefs(doc azureDocument) []string {
	refs := []string{}
	if strings.TrimSpace(doc.Extends.Template) != "" {
		refs = append(refs, strings.TrimSpace(doc.Extends.Template))
	}
	for _, stage := range doc.Stages {
		if strings.TrimSpace(stage.Template) != "" {
			refs = append(refs, strings.TrimSpace(stage.Template))
		}
		for _, job := range stage.Jobs {
			if strings.TrimSpace(job.Template) != "" {
				refs = append(refs, strings.TrimSpace(job.Template))
			}
			for _, step := range append([]azureStep(nil), append(job.Steps, job.Strategy.RunOnce.Deploy.Steps...)...) {
				if strings.TrimSpace(step.Template) != "" {
					refs = append(refs, strings.TrimSpace(step.Template))
				}
			}
		}
	}
	for _, job := range doc.Jobs {
		if strings.TrimSpace(job.Template) != "" {
			refs = append(refs, strings.TrimSpace(job.Template))
		}
		for _, step := range append([]azureStep(nil), append(job.Steps, job.Strategy.RunOnce.Deploy.Steps...)...) {
			if strings.TrimSpace(step.Template) != "" {
				refs = append(refs, strings.TrimSpace(step.Template))
			}
		}
	}
	for _, step := range doc.Steps {
		if strings.TrimSpace(step.Template) != "" {
			refs = append(refs, strings.TrimSpace(step.Template))
		}
	}
	return dedupeSlice(refs)
}

func extractAzureVariables(node *yaml.Node) ([]string, []string) {
	if node == nil || node.Kind == 0 {
		return nil, nil
	}
	work := node
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		work = node.Content[0]
	}
	names := map[string]struct{}{}
	groups := map[string]struct{}{}
	switch work.Kind {
	case yaml.MappingNode:
		for key := range mappingChildren(work) {
			if strings.TrimSpace(key) != "" {
				names[strings.TrimSpace(key)] = struct{}{}
			}
		}
	case yaml.SequenceNode:
		for _, item := range work.Content {
			mapping := mappingChildren(item)
			if group := strings.TrimSpace(mappingValue(mapping, "group")); group != "" {
				groups[group] = struct{}{}
			}
			if name := strings.TrimSpace(mappingValue(mapping, "name")); name != "" {
				names[name] = struct{}{}
			}
		}
	}
	return sortedSet(names), sortedSet(groups)
}

func normalizeAzureTemplatePath(currentPath, templatePath string) string {
	baseDir := filepath.Dir(filepath.ToSlash(strings.TrimSpace(currentPath)))
	templatePath = filepath.ToSlash(strings.TrimSpace(templatePath))
	if strings.HasPrefix(templatePath, "/") {
		return filepath.ToSlash(filepath.Clean(strings.TrimPrefix(templatePath, "/")))
	}
	return filepath.ToSlash(filepath.Clean(filepath.Join(baseDir, templatePath)))
}

func yamlDocumentNode(payload []byte) (*yaml.Node, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(payload, &root); err != nil {
		return nil, err
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return root.Content[0], nil
	}
	return &root, nil
}

func mappingChildren(node *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	if node == nil || node.Kind != yaml.MappingNode {
		return out
	}
	for idx := 0; idx+1 < len(node.Content); idx += 2 {
		key := strings.TrimSpace(node.Content[idx].Value)
		if key != "" {
			out[key] = node.Content[idx+1]
		}
	}
	return out
}

func mappingValue(values map[string]*yaml.Node, key string) string {
	node := values[key]
	if node == nil {
		return ""
	}
	return strings.TrimSpace(node.Value)
}

func normalizeStringList(values stringListField) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.ToLower(strings.TrimSpace(value)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizeStringSlice(values []any) []string {
	out := []string{}
	for _, value := range values {
		if trimmed := strings.ToLower(strings.TrimSpace(fmt.Sprint(value))); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizeDynamicValue(value any) []string {
	trimmed := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
	if trimmed == "" || trimmed == "<nil>" {
		return nil
	}
	return []string{trimmed}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sortedMapKeys(values map[string]any) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, strings.TrimSpace(key))
		}
	}
	sort.Strings(keys)
	return keys
}
