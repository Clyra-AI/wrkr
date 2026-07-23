package privilegebudget

import (
	"net/url"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/owners"
	"github.com/Clyra-AI/wrkr/core/policy/productiontargets"
)

type findingSignals struct {
	Repos       []string
	Locations   []string
	Permissions []string
	EvidenceKV  map[string][]string
	Values      []string
}

type ownershipCandidate struct {
	owner               string
	ownerSource         string
	ownershipStatus     string
	ownershipState      string
	ownershipConfidence float64
	ownershipEvidence   []string
	ownershipConflicts  []string
	ownershipDecision   *evidencepolicy.Decision
}

func Build(
	tools []agginventory.Tool,
	agents []agginventory.Agent,
	findings []model.Finding,
	productionRules *productiontargets.Config,
) (agginventory.PrivilegeBudget, []agginventory.AgentPrivilegeMapEntry) {
	writeSet := mapFromList(productiontargets.DefaultWritePermissions())
	productionConfigured := productionRules != nil
	effectiveProductionRules := productiontargets.Config{}
	if productionRules != nil {
		writeSet = mapFromList(productionRules.WritePermissions)
		effectiveProductionRules = *productionRules
	}

	signalsByAgent := buildSignalsByAgent(findings)
	signalsByRepoLocation := buildSignalsByRepoLocation(findings)
	signalsByRepo := buildSignalsByRepo(findings)
	budget := agginventory.PrivilegeBudget{
		TotalTools: len(tools),
		ProductionWrite: agginventory.ProductionWriteBudget{
			Configured: productionConfigured,
			Status:     currentProductionTargetStatus(productionConfigured),
			Count:      nil,
		},
	}
	zero := 0
	budget.ProductionWrite.Count = &zero

	for _, tool := range tools {
		writeCapable := agginventory.CanonicalWriteCapable(agginventory.ActionClassInput{
			Permissions:              tool.Permissions,
			MutableEndpointSemantics: tool.MutableEndpointSemantics,
			WriteCapable:             hasAnyPermission(tool.Permissions, writeSet),
		})
		credentialAccess := hasCredentialAccess(tool)
		execCapable := hasExecPermission(tool.Permissions)
		if writeCapable {
			budget.WriteCapableTools++
		}
		if credentialAccess {
			budget.CredentialAccessTools++
		}
		if execCapable {
			budget.ExecCapableTools++
		}

		productionWrite := false
		if productionConfigured && writeCapable {
			signal := matchingSignalsForTool(tool, signalsByAgent, signalsByRepoLocation, signalsByRepo)
			productionWrite = len(matchedProductionTargets(tool.Repos, signal, effectiveProductionRules)) > 0
			if productionWrite && budget.ProductionWrite.Count != nil {
				*budget.ProductionWrite.Count = *budget.ProductionWrite.Count + 1
			}
		}
	}

	if len(agents) == 0 {
		agentContextByID := mapAgentsByID(agents)
		entries := make([]agginventory.AgentPrivilegeMapEntry, 0, len(tools))
		for _, tool := range tools {
			writeCapable := hasAnyPermission(tool.Permissions, writeSet)
			credentialAccess := hasCredentialAccess(tool)
			execCapable := hasExecPermission(tool.Permissions)
			pullRequestWrite := hasExactPermission(tool.Permissions, "pull_request.write")
			mergeExecute := hasExactPermission(tool.Permissions, "merge.execute")
			deployWrite := hasExactPermission(tool.Permissions, "deploy.write")

			matchedTargets := []string{}
			productionWrite := false
			signal := matchingSignalsForTool(tool, signalsByAgent, signalsByRepoLocation, signalsByRepo)
			mutableEndpointSemantics := mergeMutableEndpointSemantics(tool.MutableEndpointSemantics, mutableEndpointSemanticsFromSignals(signal))
			writeCapable = agginventory.CanonicalWriteCapable(agginventory.ActionClassInput{
				Permissions:              tool.Permissions,
				MutableEndpointSemantics: mutableEndpointSemantics,
				WriteCapable:             writeCapable,
				PullRequestWrite:         pullRequestWrite,
			})
			writePathClasses := agginventory.DeriveWritePathClasses(tool.Permissions, writeCapable, pullRequestWrite, mergeExecute, deployWrite, credentialAccess, false, primaryLocation(tool), tool.ToolType)
			if productionConfigured && writeCapable {
				matchedTargets = matchedProductionTargets(tool.Repos, signal, effectiveProductionRules)
				productionWrite = len(matchedTargets) > 0
				writePathClasses = agginventory.DeriveWritePathClasses(tool.Permissions, writeCapable, pullRequestWrite, mergeExecute, deployWrite, credentialAccess, productionWrite, primaryLocation(tool), tool.ToolType)
			}

			agentContext := agentContextByID[tool.AgentID]
			deploymentStatus := strings.TrimSpace(agentContext.DeploymentStatus)
			if deploymentStatus == "" {
				deploymentStatus = "unknown"
			}
			credentials := classifyCredentialProvenances(tool.DataClass, tool.Permissions, agentContext.BoundAuthSurfaces, signal)
			credentialProvenance := agginventory.CredentialRollup(credentials, classifyCredentialProvenance(tool.DataClass, tool.Permissions, agentContext.BoundAuthSurfaces, signal))
			credentialAuthority := classifyCredentialAuthority(agentContext.BoundAuthSurfaces, signal, credentialAccess, credentials, credentialProvenance)
			authorityBindings := classifyAuthorityBindings(agentContext.BoundAuthSurfaces, signal, matchedTargets, deploymentStatus, credentialProvenance, credentialAuthority)
			actionClasses, actionReasons := agginventory.DeriveActionClasses(agginventory.ActionClassInput{
				Permissions:              tool.Permissions,
				WritePathClasses:         writePathClasses,
				MutableEndpointSemantics: mutableEndpointSemantics,
				WriteCapable:             writeCapable,
				CredentialAccess:         credentialAccess,
				DeployWrite:              deployWrite,
				ProductionWrite:          productionWrite,
				MatchedTargets:           matchedTargets,
				ToolType:                 tool.ToolType,
				Location:                 primaryLocation(tool),
			})
			standingPrivilege, standingReasons := agginventory.StandingPrivilegeFromProvenance(credentialProvenance)
			approvalReasons := approvalGapReasons(signal, tool.Permissions, deploymentStatus)
			triggerClass := workflowTriggerClass(signal, tool.Permissions, deploymentStatus, deployWrite, productionWrite)
			owner := resolveOperationalOwner(tool, tool.Repos, "", tool.Org)
			toolFamilyID := firstNonEmptyString(tool.ToolFamilyID, identity.ToolFamilyID(tool.ToolType, tool.Org))
			toolInstanceID := firstNonEmptyString(tool.ToolInstanceID, tool.ToolID)

			entries = append(entries, agginventory.AgentPrivilegeMapEntry{
				AgentID:                  tool.AgentID,
				ToolFamilyID:             toolFamilyID,
				ToolInstanceID:           toolInstanceID,
				ToolID:                   tool.ToolID,
				ToolType:                 tool.ToolType,
				Framework:                fallbackFramework(agentContext.Framework, tool.ToolType),
				Org:                      tool.Org,
				Repos:                    cloneStringSlice(tool.Repos),
				Purpose:                  strings.TrimSpace(tool.Purpose),
				PurposeSource:            strings.TrimSpace(tool.PurposeSource),
				PurposeConfidence:        strings.TrimSpace(tool.PurposeConfidence),
				Version:                  strings.TrimSpace(tool.Version),
				VersionSource:            strings.TrimSpace(tool.VersionSource),
				ConfigFingerprint:        strings.TrimSpace(tool.ConfigFingerprint),
				ConfigSource:             strings.TrimSpace(tool.ConfigSource),
				DeliveryHarnesses:        deliveryHarnesses(signal, tool.ToolType, primaryLocation(tool)),
				ResolverRefs:             resolverRefs(signal, primaryLocation(tool)),
				EvalConfigRefs:           evalConfigRefs(signal, primaryLocation(tool)),
				DryRunRequired:           dryRunRequired(signal),
				SandboxGates:             sandboxGates(signal),
				TestGates:                testGates(signal),
				ValidationRequirements:   validationRequirements(signal),
				Permissions:              cloneStringSlice(tool.Permissions),
				WritePathClasses:         writePathClasses,
				ActionClasses:            actionClasses,
				ActionReasons:            actionReasons,
				MutableEndpointSemantics: mutableEndpointSemantics,
				Location:                 primaryLocation(tool),
				EndpointClass:            tool.EndpointClass,
				DataClass:                tool.DataClass,
				AutonomyLevel:            tool.AutonomyLevel,
				RiskScore:                tool.RiskScore,
				ApprovalClassification:   strings.TrimSpace(tool.ApprovalClass),
				BoundTools:               cloneStringSlice(agentContext.BoundTools),
				BoundDataSources:         cloneStringSlice(agentContext.BoundDataSources),
				BoundAuthSurfaces:        cloneStringSlice(agentContext.BoundAuthSurfaces),
				BindingEvidenceKeys:      cloneStringSlice(agentContext.BindingEvidenceKeys),
				MissingBindings:          cloneStringSlice(agentContext.MissingBindings),
				DeploymentStatus:         deploymentStatus,
				DeploymentArtifacts:      cloneStringSlice(agentContext.DeploymentArtifacts),
				DeploymentEvidenceKeys:   cloneStringSlice(agentContext.DeploymentEvidenceKeys),
				WorkflowTriggerClass:     triggerClass,
				OperationalOwner:         owner.Owner,
				OwnerSource:              owner.OwnerSource,
				OwnershipStatus:          owner.OwnershipStatus,
				OwnershipState:           owner.OwnershipState,
				OwnershipConfidence:      owner.OwnershipConfidence,
				OwnershipEvidence:        cloneStringSlice(owner.EvidenceBasis),
				OwnershipConflicts:       cloneStringSlice(owner.ConflictOwners),
				OwnershipDecision:        cloneEvidenceDecision(owner.EvidenceDecision),
				ApprovalGapReasons:       approvalReasons,
				TrustDepth:               agginventory.CloneTrustDepth(tool.TrustDepth),
				PullRequestWrite:         pullRequestWrite,
				MergeExecute:             mergeExecute,
				DeployWrite:              deployWrite,
				DeliveryChainStatus:      deliveryChainStatus(pullRequestWrite, mergeExecute, deployWrite),
				ProductionTargetStatus:   currentProductionTargetStatus(productionConfigured),
				WriteCapable:             writeCapable,
				CredentialAccess:         credentialAccess,
				Credentials:              credentials,
				CredentialProvenance:     credentialProvenance,
				CredentialAuthority:      credentialAuthority,
				AuthorityBindings:        authorityBindings,
				PathContext:              agginventory.ClassifyPathContext(primaryLocation(tool)),
				StandingPrivilege:        standingPrivilege,
				StandingPrivilegeReasons: standingReasons,
				ExecCapable:              execCapable,
				ProductionWrite:          productionWrite,
				MatchedProductionTargets: append([]string(nil), matchedTargets...),
			})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].AgentID != entries[j].AgentID {
				return entries[i].AgentID < entries[j].AgentID
			}
			if entries[i].ToolType != entries[j].ToolType {
				return entries[i].ToolType < entries[j].ToolType
			}
			return entries[i].ToolID < entries[j].ToolID
		})
		return budget, entries
	}

	entries := buildInstanceEntries(tools, agents, findings, writeSet, productionRules, productionConfigured)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Org != entries[j].Org {
			return entries[i].Org < entries[j].Org
		}
		if entries[i].Framework != entries[j].Framework {
			return entries[i].Framework < entries[j].Framework
		}
		if entries[i].Location != entries[j].Location {
			return entries[i].Location < entries[j].Location
		}
		iStart, iEnd := locationRangeBounds(entries[i].LocationRange)
		jStart, jEnd := locationRangeBounds(entries[j].LocationRange)
		if iStart != jStart {
			return iStart < jStart
		}
		if iEnd != jEnd {
			return iEnd < jEnd
		}
		if entries[i].AgentInstanceID != entries[j].AgentInstanceID {
			return entries[i].AgentInstanceID < entries[j].AgentInstanceID
		}
		if entries[i].Symbol != entries[j].Symbol {
			return entries[i].Symbol < entries[j].Symbol
		}
		return entries[i].AgentID < entries[j].AgentID
	})

	return budget, entries
}

func mapAgentsByID(agents []agginventory.Agent) map[string]agginventory.Agent {
	out := map[string]agginventory.Agent{}
	for _, agent := range agents {
		keys := agentLookupKeys(agent)
		if len(keys) == 0 {
			continue
		}
		for _, key := range keys {
			current := out[key]
			out[key] = mergeAgentContext(current, agent, key)
		}
	}
	return out
}

func buildInstanceEntries(
	tools []agginventory.Tool,
	agents []agginventory.Agent,
	findings []model.Finding,
	writeSet map[string]struct{},
	productionRules *productiontargets.Config,
	productionConfigured bool,
) []agginventory.AgentPrivilegeMapEntry {
	signalsByInstance := buildSignalsByInstance(findings)
	signalsByRepoLocation := buildSignalsByRepoLocation(findings)
	signalsByRepo := buildSignalsByRepo(findings)
	effectiveProductionRules := productiontargets.Config{}
	if productionRules != nil {
		effectiveProductionRules = *productionRules
	}
	toolIndex := buildToolIndex(tools)
	entries := make([]agginventory.AgentPrivilegeMapEntry, 0, len(agents))

	for _, agent := range agents {
		instanceID := strings.TrimSpace(agent.AgentInstanceID)
		if instanceID == "" {
			continue
		}
		tool := lookupToolForAgent(agent, toolIndex)
		scopedSignals := signalsByInstance[strings.TrimSpace(agent.ToolInstanceID)]
		if isEmptyFindingSignals(scopedSignals) {
			scopedSignals = signalsByInstance[instanceID]
		}
		signals := mergeFindingSignalSets(
			scopedSignals,
			matchingSignalsForAgent(agent, tool, signalsByRepoLocation, signalsByRepo),
		)
		permissions := cloneStringSlice(signals.Permissions)
		if len(permissions) == 0 {
			permissions = cloneStringSlice(tool.Permissions)
		}
		repos := cloneStringSlice(signals.Repos)
		if len(repos) == 0 && strings.TrimSpace(agent.Repo) != "" {
			repos = []string{strings.TrimSpace(agent.Repo)}
		}
		if len(repos) == 0 {
			repos = cloneStringSlice(tool.Repos)
		}

		framework := fallbackFramework(agent.Framework, tool.ToolType)
		toolID := tool.ToolID
		if strings.TrimSpace(toolID) == "" {
			toolID = identity.ToolID(framework, agent.Location)
		}
		org := strings.TrimSpace(agent.Org)
		if org == "" {
			org = fallbackOrg(tool.Org)
		}
		toolFamilyID := firstNonEmptyString(agent.ToolFamilyID, tool.ToolFamilyID, identity.ToolFamilyID(framework, org))
		toolInstanceID := firstNonEmptyString(agent.ToolInstanceID, tool.ToolInstanceID, identity.ToolInstanceID(framework, firstRepo(repos), agent.Location, agent.Symbol, rangeStart(agent.LocationRange), rangeEnd(agent.LocationRange)))
		endpointClass := firstNonEmptyString(tool.EndpointClass, "workspace")
		dataClass := firstNonEmptyString(tool.DataClass, inferAgentDataClass(agent, permissions))
		autonomyLevel := firstNonEmptyString(tool.AutonomyLevel, "interactive")
		riskScore := tool.RiskScore
		approvalClassification := strings.TrimSpace(tool.ApprovalClass)
		if approvalClassification == "" {
			approvalClassification = "unapproved"
		}

		mutableEndpointSemantics := mergeMutableEndpointSemantics(tool.MutableEndpointSemantics, mutableEndpointSemanticsFromSignals(signals))
		writeCapable := hasAnyPermission(permissions, writeSet)
		credentialAccess := hasCredentialAccessForSurface(dataClass, permissions, agent.BoundAuthSurfaces)
		execCapable := hasExecPermission(permissions)
		pullRequestWrite := hasExactPermission(permissions, "pull_request.write")
		mergeExecute := hasExactPermission(permissions, "merge.execute")
		deployWrite := hasExactPermission(permissions, "deploy.write")
		writeCapable = agginventory.CanonicalWriteCapable(agginventory.ActionClassInput{
			Permissions:              permissions,
			MutableEndpointSemantics: mutableEndpointSemantics,
			WriteCapable:             writeCapable,
			PullRequestWrite:         pullRequestWrite,
			MergeExecute:             mergeExecute,
			DeployWrite:              deployWrite,
		})
		writePathClasses := agginventory.DeriveWritePathClasses(permissions, writeCapable, pullRequestWrite, mergeExecute, deployWrite, credentialAccess, false, agent.Location, framework)
		matchedTargets := []string{}
		productionWrite := false
		if productionConfigured && writeCapable {
			matchedTargets = matchedProductionTargets(repos, signals, effectiveProductionRules)
			productionWrite = len(matchedTargets) > 0
			writePathClasses = agginventory.DeriveWritePathClasses(permissions, writeCapable, pullRequestWrite, mergeExecute, deployWrite, credentialAccess, productionWrite, agent.Location, framework)
		}

		deploymentStatus := strings.TrimSpace(agent.DeploymentStatus)
		if deploymentStatus == "" {
			deploymentStatus = "unknown"
		}
		credentials := classifyCredentialProvenances(dataClass, permissions, agent.BoundAuthSurfaces, signals)
		credentialProvenance := agginventory.CredentialRollup(credentials, classifyCredentialProvenance(dataClass, permissions, agent.BoundAuthSurfaces, signals))
		credentialAuthority := classifyCredentialAuthority(agent.BoundAuthSurfaces, signals, credentialAccess, credentials, credentialProvenance)
		authorityBindings := classifyAuthorityBindings(agent.BoundAuthSurfaces, signals, matchedTargets, deploymentStatus, credentialProvenance, credentialAuthority)
		actionClasses, actionReasons := agginventory.DeriveActionClasses(agginventory.ActionClassInput{
			Permissions:              permissions,
			WritePathClasses:         writePathClasses,
			MutableEndpointSemantics: mutableEndpointSemantics,
			WriteCapable:             writeCapable,
			CredentialAccess:         credentialAccess,
			DeployWrite:              deployWrite,
			ProductionWrite:          productionWrite,
			MatchedTargets:           matchedTargets,
			ToolType:                 framework,
			Location:                 agent.Location,
		})
		standingPrivilege, standingReasons := agginventory.StandingPrivilegeFromProvenance(credentialProvenance)
		approvalReasons := approvalGapReasons(signals, permissions, deploymentStatus)
		triggerClass := workflowTriggerClass(signals, permissions, deploymentStatus, deployWrite, productionWrite)
		owner := resolveOperationalOwner(tool, repos, strings.TrimSpace(agent.Location), org)

		entries = append(entries, agginventory.AgentPrivilegeMapEntry{
			AgentID:                  strings.TrimSpace(agent.AgentID),
			AgentInstanceID:          instanceID,
			ToolFamilyID:             toolFamilyID,
			ToolInstanceID:           toolInstanceID,
			ToolID:                   toolID,
			ToolType:                 firstNonEmptyString(tool.ToolType, framework),
			Framework:                framework,
			Symbol:                   strings.TrimSpace(agent.Symbol),
			Purpose:                  firstNonEmptyString(strings.TrimSpace(agent.Purpose), strings.TrimSpace(tool.Purpose)),
			PurposeSource:            firstNonEmptyString(strings.TrimSpace(agent.PurposeSource), strings.TrimSpace(tool.PurposeSource)),
			PurposeConfidence:        firstNonEmptyString(strings.TrimSpace(agent.PurposeConfidence), strings.TrimSpace(tool.PurposeConfidence)),
			Version:                  firstNonEmptyString(strings.TrimSpace(agent.Version), strings.TrimSpace(tool.Version)),
			VersionSource:            firstNonEmptyString(strings.TrimSpace(agent.VersionSource), strings.TrimSpace(tool.VersionSource)),
			ConfigFingerprint:        firstNonEmptyString(strings.TrimSpace(agent.ConfigFingerprint), strings.TrimSpace(tool.ConfigFingerprint)),
			ConfigSource:             firstNonEmptyString(strings.TrimSpace(agent.ConfigSource), strings.TrimSpace(tool.ConfigSource)),
			DeliveryHarnesses:        deliveryHarnesses(signals, firstNonEmptyString(tool.ToolType, framework), strings.TrimSpace(agent.Location)),
			ResolverRefs:             resolverRefs(signals, strings.TrimSpace(agent.Location)),
			EvalConfigRefs:           evalConfigRefs(signals, strings.TrimSpace(agent.Location)),
			DryRunRequired:           dryRunRequired(signals),
			SandboxGates:             sandboxGates(signals),
			TestGates:                testGates(signals),
			ValidationRequirements:   validationRequirements(signals),
			Org:                      org,
			Repos:                    repos,
			Permissions:              permissions,
			WritePathClasses:         writePathClasses,
			ActionClasses:            actionClasses,
			ActionReasons:            actionReasons,
			MutableEndpointSemantics: mutableEndpointSemantics,
			Location:                 strings.TrimSpace(agent.Location),
			LocationRange:            cloneLocationRange(agent.LocationRange),
			EndpointClass:            endpointClass,
			DataClass:                dataClass,
			AutonomyLevel:            autonomyLevel,
			RiskScore:                riskScore,
			ApprovalClassification:   approvalClassification,
			BoundTools:               cloneStringSlice(agent.BoundTools),
			BoundDataSources:         cloneStringSlice(agent.BoundDataSources),
			BoundAuthSurfaces:        cloneStringSlice(agent.BoundAuthSurfaces),
			BindingEvidenceKeys:      cloneStringSlice(agent.BindingEvidenceKeys),
			MissingBindings:          cloneStringSlice(agent.MissingBindings),
			DeploymentStatus:         deploymentStatus,
			DeploymentArtifacts:      cloneStringSlice(agent.DeploymentArtifacts),
			DeploymentEvidenceKeys:   cloneStringSlice(agent.DeploymentEvidenceKeys),
			WorkflowTriggerClass:     triggerClass,
			OperationalOwner:         owner.Owner,
			OwnerSource:              owner.OwnerSource,
			OwnershipStatus:          owner.OwnershipStatus,
			OwnershipState:           owner.OwnershipState,
			OwnershipConfidence:      owner.OwnershipConfidence,
			OwnershipEvidence:        cloneStringSlice(owner.EvidenceBasis),
			OwnershipConflicts:       cloneStringSlice(owner.ConflictOwners),
			OwnershipDecision:        cloneEvidenceDecision(owner.EvidenceDecision),
			ApprovalGapReasons:       approvalReasons,
			TrustDepth:               agginventory.CloneTrustDepth(tool.TrustDepth),
			PullRequestWrite:         pullRequestWrite,
			MergeExecute:             mergeExecute,
			DeployWrite:              deployWrite,
			DeliveryChainStatus:      deliveryChainStatus(pullRequestWrite, mergeExecute, deployWrite),
			ProductionTargetStatus:   currentProductionTargetStatus(productionConfigured),
			WriteCapable:             writeCapable,
			CredentialAccess:         credentialAccess,
			Credentials:              credentials,
			CredentialProvenance:     credentialProvenance,
			CredentialAuthority:      credentialAuthority,
			AuthorityBindings:        authorityBindings,
			PathContext:              agginventory.ClassifyPathContext(agent.Location),
			StandingPrivilege:        standingPrivilege,
			StandingPrivilegeReasons: standingReasons,
			ExecCapable:              execCapable,
			ProductionWrite:          productionWrite,
			MatchedProductionTargets: append([]string(nil), matchedTargets...),
		})
	}

	return entries
}

func buildSignalsByInstance(findings []model.Finding) map[string]findingSignals {
	out := map[string]findingSignals{}
	for _, finding := range findings {
		for _, instanceID := range agentInstanceKeysForFinding(finding) {
			if instanceID == "" {
				continue
			}
			entry := out[instanceID]
			if entry.EvidenceKV == nil {
				entry.EvidenceKV = map[string][]string{}
			}
			mergeFindingSignal(&entry, finding)
			out[instanceID] = entry
		}
	}
	for key, entry := range out {
		out[key] = normalizeFindingSignals(entry)
	}
	return out
}

func agentInstanceKeysForFinding(finding model.Finding) []string {
	legacy := agentInstanceIDForFinding(finding)
	symbol, startLine, endLine := agentIdentityPartsForFinding(finding)
	scoped := identity.ToolInstanceID(finding.ToolType, finding.Repo, finding.Location, symbol, startLine, endLine)
	if scoped == legacy {
		return []string{scoped}
	}
	return []string{scoped, legacy}
}

func mergeFindingSignal(entry *findingSignals, finding model.Finding) {
	if entry == nil {
		return
	}
	if repo := strings.TrimSpace(finding.Repo); repo != "" {
		entry.Repos = append(entry.Repos, repo)
		entry.Values = append(entry.Values, normalizeToken(repo))
	}
	if location := strings.TrimSpace(finding.Location); location != "" {
		entry.Locations = append(entry.Locations, location)
		entry.Values = append(entry.Values, normalizeToken(location))
		entry.Values = append(entry.Values, extractHost(location)...)
	}
	entry.Permissions = append(entry.Permissions, finding.Permissions...)
	for _, permission := range finding.Permissions {
		if normalized := normalizeToken(permission); normalized != "" {
			entry.Values = append(entry.Values, normalized)
		}
	}
	for _, evidence := range finding.Evidence {
		key := normalizeToken(evidence.Key)
		value := strings.TrimSpace(evidence.Value)
		normalizedValue := normalizeToken(value)
		if key != "" {
			entry.Values = append(entry.Values, key)
		}
		if normalizedValue != "" {
			entry.Values = append(entry.Values, normalizedValue)
			entry.Values = append(entry.Values, extractHost(value)...)
		}
		if key != "" && normalizedValue != "" {
			entry.EvidenceKV[key] = append(entry.EvidenceKV[key], normalizedValue)
		}
	}
}

func normalizeFindingSignals(entry findingSignals) findingSignals {
	entry.Repos = dedupeSortedPreserveCase(entry.Repos)
	entry.Locations = dedupeSortedPreserveCase(entry.Locations)
	entry.Permissions = dedupeSortedPreserveCase(entry.Permissions)
	entry.Values = dedupeSorted(entry.Values)
	for key, values := range entry.EvidenceKV {
		entry.EvidenceKV[key] = dedupeSorted(values)
	}
	return entry
}

func normalizeAgentFindingSignals(entry findingSignals) findingSignals {
	entry.Repos = dedupeSorted(entry.Repos)
	entry.Locations = dedupeSorted(entry.Locations)
	entry.Permissions = dedupeSorted(entry.Permissions)
	entry.Values = dedupeSorted(entry.Values)
	for key, values := range entry.EvidenceKV {
		entry.EvidenceKV[key] = dedupeSorted(values)
	}
	return entry
}

func mergeFindingSignalSets(groups ...findingSignals) findingSignals {
	merged := findingSignals{EvidenceKV: map[string][]string{}}
	for _, group := range groups {
		merged.Repos = append(merged.Repos, group.Repos...)
		merged.Locations = append(merged.Locations, group.Locations...)
		merged.Permissions = append(merged.Permissions, group.Permissions...)
		merged.Values = append(merged.Values, group.Values...)
		for key, values := range group.EvidenceKV {
			merged.EvidenceKV[key] = append(merged.EvidenceKV[key], values...)
		}
	}
	return normalizeFindingSignals(merged)
}

func isEmptyFindingSignals(entry findingSignals) bool {
	return len(entry.Repos) == 0 &&
		len(entry.Locations) == 0 &&
		len(entry.Permissions) == 0 &&
		len(entry.Values) == 0 &&
		len(entry.EvidenceKV) == 0
}

func repoLocationSignalKey(org string, repo string, location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	return strings.Join([]string{fallbackOrg(org), strings.TrimSpace(repo), location}, "|")
}

type toolIndex struct {
	byRepoLocation map[string]agginventory.Tool
	byLocation     map[string]agginventory.Tool
}

func buildToolIndex(tools []agginventory.Tool) toolIndex {
	index := toolIndex{
		byRepoLocation: map[string]agginventory.Tool{},
		byLocation:     map[string]agginventory.Tool{},
	}
	for _, tool := range tools {
		org := fallbackOrg(tool.Org)
		framework := strings.TrimSpace(tool.ToolType)
		for _, location := range tool.Locations {
			repo := strings.TrimSpace(location.Repo)
			path := strings.TrimSpace(location.Location)
			if path == "" {
				continue
			}
			index.byLocation[org+"::"+framework+"::"+path] = tool
			if repo != "" {
				index.byRepoLocation[org+"::"+framework+"::"+repo+"::"+path] = tool
			}
		}
	}
	return index
}

func lookupToolForAgent(agent agginventory.Agent, index toolIndex) agginventory.Tool {
	org := fallbackOrg(agent.Org)
	framework := strings.TrimSpace(agent.Framework)
	location := strings.TrimSpace(agent.Location)
	repo := strings.TrimSpace(agent.Repo)
	if repo != "" {
		if item, ok := index.byRepoLocation[org+"::"+framework+"::"+repo+"::"+location]; ok {
			return item
		}
	}
	if item, ok := index.byLocation[org+"::"+framework+"::"+location]; ok {
		return item
	}
	return agginventory.Tool{}
}

func agentInstanceIDForFinding(finding model.Finding) string {
	symbol, startLine, endLine := agentIdentityPartsForFinding(finding)
	return identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
}

func agentIdentityPartsForFinding(finding model.Finding) (string, int, int) {
	symbol := ""
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key == "symbol" || key == "name" || key == "agent_name" || key == "workflow_name" || key == "operation_id" {
			symbol = strings.TrimSpace(evidence.Value)
			break
		}
	}
	startLine := 0
	endLine := 0
	if finding.LocationRange != nil {
		startLine = finding.LocationRange.StartLine
		endLine = finding.LocationRange.EndLine
	}
	return symbol, startLine, endLine
}

func inferAgentDataClass(agent agginventory.Agent, permissions []string) string {
	for _, item := range agent.BoundDataSources {
		lower := normalizeToken(item)
		switch {
		case strings.Contains(lower, "db"), strings.Contains(lower, "warehouse"), strings.Contains(lower, "table"), strings.Contains(lower, "dataset"), strings.Contains(lower, "postgres"):
			return "database"
		case strings.Contains(lower, "customer"), strings.Contains(lower, "profile"), strings.Contains(lower, "user"):
			return "pii"
		}
	}
	for _, item := range permissions {
		lower := normalizeToken(item)
		switch {
		case strings.Contains(lower, "secret"), strings.Contains(lower, "token"), strings.Contains(lower, "credential"):
			return "credentials"
		case strings.Contains(lower, "db.write"), strings.Contains(lower, "db.read"):
			return "database"
		}
	}
	return "code"
}

func agentLookupKeys(agent agginventory.Agent) []string {
	keys := map[string]struct{}{}
	if agentID := strings.TrimSpace(agent.AgentID); agentID != "" {
		keys[agentID] = struct{}{}
	}
	framework := strings.TrimSpace(agent.Framework)
	location := strings.TrimSpace(agent.Location)
	if framework != "" && location != "" {
		toolScoped := identity.AgentID(identity.ToolID(framework, location), fallbackOrg(agent.Org))
		keys[toolScoped] = struct{}{}
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func mergeAgentContext(current, incoming agginventory.Agent, key string) agginventory.Agent {
	merged := current
	if strings.TrimSpace(merged.AgentID) == "" {
		merged.AgentID = strings.TrimSpace(key)
	}
	if strings.TrimSpace(merged.AgentInstanceID) == "" {
		merged.AgentInstanceID = strings.TrimSpace(incoming.AgentInstanceID)
	}
	if strings.TrimSpace(merged.ToolFamilyID) == "" {
		merged.ToolFamilyID = strings.TrimSpace(incoming.ToolFamilyID)
	}
	if strings.TrimSpace(merged.ToolInstanceID) == "" {
		merged.ToolInstanceID = strings.TrimSpace(incoming.ToolInstanceID)
	}
	if strings.TrimSpace(merged.Framework) == "" {
		merged.Framework = strings.TrimSpace(incoming.Framework)
	}
	merged.BoundTools = dedupeSorted(append(append([]string(nil), merged.BoundTools...), incoming.BoundTools...))
	merged.BoundDataSources = dedupeSorted(append(append([]string(nil), merged.BoundDataSources...), incoming.BoundDataSources...))
	merged.BoundAuthSurfaces = dedupeSorted(append(append([]string(nil), merged.BoundAuthSurfaces...), incoming.BoundAuthSurfaces...))
	merged.BindingEvidenceKeys = dedupeSorted(append(append([]string(nil), merged.BindingEvidenceKeys...), incoming.BindingEvidenceKeys...))
	merged.MissingBindings = dedupeSorted(append(append([]string(nil), merged.MissingBindings...), incoming.MissingBindings...))
	merged.DeploymentStatus = mergeDeploymentStatus(merged.DeploymentStatus, incoming.DeploymentStatus)
	merged.DeploymentArtifacts = dedupeSortedPreserveCase(append(append([]string(nil), merged.DeploymentArtifacts...), incoming.DeploymentArtifacts...))
	merged.DeploymentEvidenceKeys = dedupeSortedPreserveCase(append(append([]string(nil), merged.DeploymentEvidenceKeys...), incoming.DeploymentEvidenceKeys...))
	return merged
}

func mergeDeploymentStatus(current, incoming string) string {
	currentNormalized := normalizeToken(current)
	incomingNormalized := normalizeToken(incoming)
	switch {
	case currentNormalized == "deployed" || incomingNormalized == "deployed":
		return "deployed"
	case currentNormalized == "" || currentNormalized == "unknown":
		if incomingNormalized != "" {
			return incomingNormalized
		}
	case incomingNormalized == "" || incomingNormalized == "unknown":
		if currentNormalized != "" {
			return currentNormalized
		}
	}
	if currentNormalized == "" {
		return incomingNormalized
	}
	if incomingNormalized == "" {
		return currentNormalized
	}
	if currentNormalized <= incomingNormalized {
		return currentNormalized
	}
	return incomingNormalized
}

func buildSignalsByAgent(findings []model.Finding) map[string]findingSignals {
	out := map[string]findingSignals{}
	for _, finding := range findings {
		agentID := identity.AgentID(identity.ToolID(finding.ToolType, finding.Location), fallbackOrg(finding.Org))
		entry := out[agentID]
		if entry.EvidenceKV == nil {
			entry.EvidenceKV = map[string][]string{}
		}
		if repo := normalizeToken(finding.Repo); repo != "" {
			entry.Repos = append(entry.Repos, repo)
			entry.Values = append(entry.Values, repo)
		}
		if location := normalizeToken(finding.Location); location != "" {
			entry.Locations = append(entry.Locations, location)
			entry.Values = append(entry.Values, location)
			entry.Values = append(entry.Values, extractHost(location)...)
		}
		entry.Permissions = append(entry.Permissions, finding.Permissions...)
		for _, permission := range finding.Permissions {
			if normalized := normalizeToken(permission); normalized != "" {
				entry.Values = append(entry.Values, normalized)
			}
		}
		for _, evidence := range finding.Evidence {
			key := normalizeToken(evidence.Key)
			value := normalizeToken(evidence.Value)
			if key != "" {
				entry.Values = append(entry.Values, key)
			}
			if value != "" {
				entry.Values = append(entry.Values, value)
				entry.Values = append(entry.Values, extractHost(value)...)
			}
			if key != "" && value != "" {
				entry.EvidenceKV[key] = append(entry.EvidenceKV[key], value)
			}
		}
		out[agentID] = entry
	}
	for key, entry := range out {
		out[key] = normalizeAgentFindingSignals(entry)
	}
	return out
}

func buildSignalsByRepoLocation(findings []model.Finding) map[string]findingSignals {
	out := map[string]findingSignals{}
	for _, finding := range findings {
		key := repoLocationSignalKey(finding.Org, finding.Repo, finding.Location)
		if key == "" {
			continue
		}
		entry := out[key]
		if entry.EvidenceKV == nil {
			entry.EvidenceKV = map[string][]string{}
		}
		mergeFindingSignal(&entry, finding)
		out[key] = entry
	}
	for key, entry := range out {
		out[key] = normalizeFindingSignals(entry)
	}
	return out
}

func buildSignalsByRepo(findings []model.Finding) map[string]findingSignals {
	out := map[string]findingSignals{}
	for _, finding := range findings {
		repo := strings.TrimSpace(finding.Repo)
		if repo == "" {
			continue
		}
		key := strings.Join([]string{fallbackOrg(finding.Org), repo}, "|")
		entry := out[key]
		if entry.EvidenceKV == nil {
			entry.EvidenceKV = map[string][]string{}
		}
		mergeFindingSignal(&entry, finding)
		out[key] = entry
	}
	for key, entry := range out {
		out[key] = normalizeFindingSignals(entry)
	}
	return out
}

func matchingSignalsForTool(tool agginventory.Tool, signalsByAgent map[string]findingSignals, signalsByRepoLocation map[string]findingSignals, signalsByRepo map[string]findingSignals) findingSignals {
	repoWide := repoWideSignalsForTool(tool.ToolType, tool.Org, tool.Repos, signalsByRepo)
	if signal := signalsByAgent[strings.TrimSpace(tool.AgentID)]; !isEmptyFindingSignals(signal) {
		return mergeFindingSignalSets(signal, repoWide)
	}
	location := strings.TrimSpace(primaryLocation(tool))
	if location == "" {
		return repoWide
	}
	merged := findingSignals{}
	for _, repo := range tool.Repos {
		if signal := signalsByRepoLocation[repoLocationSignalKey(tool.Org, repo, location)]; !isEmptyFindingSignals(signal) {
			merged = mergeFindingSignalSets(merged, signal)
		}
	}
	return mergeFindingSignalSets(merged, signalsByRepoLocation[repoLocationSignalKey(tool.Org, "", location)], repoWide)
}

func matchingSignalsForAgent(agent agginventory.Agent, tool agginventory.Tool, signalsByRepoLocation map[string]findingSignals, signalsByRepo map[string]findingSignals) findingSignals {
	location := strings.TrimSpace(agent.Location)
	if location == "" {
		location = strings.TrimSpace(primaryLocation(tool))
	}
	if location == "" {
		return findingSignals{}
	}

	repos := []string{}
	if strings.TrimSpace(agent.Repo) != "" {
		repos = append(repos, strings.TrimSpace(agent.Repo))
	} else {
		repos = append(repos, tool.Repos...)
	}
	repos = dedupeSortedPreserveCase(repos)

	merged := findingSignals{}
	for _, repo := range repos {
		merged = mergeFindingSignalSets(merged, filteredRepoLocationSignals(signalsByRepoLocation[repoLocationSignalKey(agent.Org, repo, location)]))
	}
	if repoWideEligibleToolType(firstNonEmptyString(tool.ToolType, agent.Framework)) {
		return mergeFindingSignalSets(
			merged,
			filteredRepoLocationSignals(signalsByRepoLocation[repoLocationSignalKey(agent.Org, "", location)]),
			repoWideSignalsForTool(firstNonEmptyString(tool.ToolType, agent.Framework), agent.Org, repos, signalsByRepo),
		)
	}
	return mergeFindingSignalSets(merged, filteredRepoLocationSignals(signalsByRepoLocation[repoLocationSignalKey(agent.Org, "", location)]))
}

func filteredRepoLocationSignals(signal findingSignals) findingSignals {
	if isEmptyFindingSignals(signal) {
		return findingSignals{}
	}
	out := findingSignals{
		Repos:      append([]string(nil), signal.Repos...),
		Values:     []string{},
		EvidenceKV: map[string][]string{},
	}
	allowedKeys := map[string]struct{}{
		"workflow_secret_refs":               {},
		"workflow_noncredential_secret_refs": {},
		"workflow_credential_kind":           {},
		"credential_keys":                    {},
		"credential_provenance_type":         {},
		"credential_subject":                 {},
		"credential_scope":                   {},
		"credential_confidence":              {},
		"workflow_builtin_token":             {},
		"workflow_token_permission":          {},
		"identity_type":                      {},
		"subject":                            {},
		"workflow_triggers":                  {},
		"approval_source":                    {},
		"deployment_gate":                    {},
		"human_gate":                         {},
		"mutable_endpoint_semantic":          {},
		"auto_deploy":                        {},
		"proof_requirement":                  {},
		"env_key":                            {},
		"env_value":                          {},
		"server":                             {},
		"url":                                {},
		"authority_binding":                  {},
		"workflow_environment":               {},
		"target_class_hint":                  {},
		"credential_target_system":           {},
		"credential_likely_scope":            {},
		"credential_scope_confidence":        {},
		"delivery_harness":                   {},
		"resolver_ref":                       {},
		"eval_config_ref":                    {},
		"dry_run_required":                   {},
		"sandbox_gate":                       {},
		"test_gate":                          {},
		"validation_requirement":             {},
	}
	for key, values := range signal.EvidenceKV {
		if _, ok := allowedKeys[key]; !ok {
			continue
		}
		out.EvidenceKV[key] = append([]string(nil), values...)
		out.Values = append(out.Values, key)
		out.Values = append(out.Values, values...)
	}
	out.Values = append(out.Values, out.Repos...)
	return normalizeFindingSignals(out)
}

func repoWideSignalsForRepos(org string, repos []string, signalsByRepo map[string]findingSignals) findingSignals {
	merged := findingSignals{}
	for _, repo := range dedupeSortedPreserveCase(repos) {
		key := strings.Join([]string{fallbackOrg(org), strings.TrimSpace(repo)}, "|")
		merged = mergeFindingSignalSets(merged, filteredRepoLocationSignals(signalsByRepo[key]))
	}
	return merged
}

func repoWideSignalsForTool(toolType, org string, repos []string, signalsByRepo map[string]findingSignals) findingSignals {
	if !repoWideEligibleToolType(toolType) {
		return findingSignals{}
	}
	merged := repoWideSignalsForRepos(org, repos, signalsByRepo)
	if !targetContextAuthorityFilteringRequired(toolType) {
		return merged
	}
	return stripRepoWideAuthoritySignals(merged)
}

func targetContextAuthorityFilteringRequired(toolType string) bool {
	switch normalizeToken(toolType) {
	case "openapi", "route":
		return true
	default:
		return false
	}
}

func stripRepoWideAuthoritySignals(signal findingSignals) findingSignals {
	if isEmptyFindingSignals(signal) {
		return findingSignals{}
	}
	blockedKeys := map[string]struct{}{
		"workflow_secret_refs":               {},
		"workflow_noncredential_secret_refs": {},
		"workflow_credential_kind":           {},
		"credential_keys":                    {},
		"credential_provenance_type":         {},
		"credential_subject":                 {},
		"credential_scope":                   {},
		"credential_confidence":              {},
		"workflow_builtin_token":             {},
		"workflow_token_permission":          {},
		"identity_type":                      {},
		"subject":                            {},
		"authority_binding":                  {},
		"credential_target_system":           {},
		"credential_likely_scope":            {},
		"credential_scope_confidence":        {},
	}
	out := findingSignals{
		Repos:      append([]string(nil), signal.Repos...),
		Locations:  append([]string(nil), signal.Locations...),
		Values:     []string{},
		EvidenceKV: map[string][]string{},
	}
	for key, values := range signal.EvidenceKV {
		if _, blocked := blockedKeys[key]; blocked {
			continue
		}
		out.EvidenceKV[key] = append([]string(nil), values...)
		out.Values = append(out.Values, key)
		out.Values = append(out.Values, values...)
	}
	out.Values = append(out.Values, out.Repos...)
	out.Values = append(out.Values, out.Locations...)
	return normalizeFindingSignals(out)
}

func repoWideEligibleToolType(toolType string) bool {
	switch normalizeToken(toolType) {
	case "openapi", "route":
		return true
	default:
		return false
	}
}

func matchedProductionTargets(
	repos []string,
	signals findingSignals,
	rules productiontargets.Config,
) []string {
	matches := map[string]struct{}{}
	if rules.HasTargets() {
		addMatchSet(matches, "repo", rules.Targets.Repos, append(append([]string(nil), repos...), signals.Repos...))
		addMatchSet(matches, "mcp_server", rules.Targets.MCPServers, signals.EvidenceKV["server"])
		hostCandidates := append([]string{}, signals.EvidenceKV["url"]...)
		hostCandidates = append(hostCandidates, signals.Values...)
		addMatchSet(matches, "host", rules.Targets.Hosts, hostCandidates)

		envKeyCandidates := append([]string{}, signals.EvidenceKV["env_key"]...)
		envKeyCandidates = append(envKeyCandidates, signals.Values...)
		addMatchSet(matches, "workflow_env_key", rules.Targets.WorkflowEnvKeys, envKeyCandidates)

		envValueCandidates := append([]string{}, signals.EvidenceKV["env_value"]...)
		envValueCandidates = append(envValueCandidates, signals.Values...)
		addMatchSet(matches, "workflow_env_value", rules.Targets.WorkflowEnvValues, envValueCandidates)

		out := make([]string, 0, len(matches))
		for item := range matches {
			out = append(out, item)
		}
		sort.Strings(out)
		return out
	}

	for _, item := range productiontargets.MatchBuiltInTargets(productiontargets.BuiltInMatchInput{
		Repos:       append(append([]string(nil), repos...), signals.Repos...),
		Locations:   append([]string(nil), signals.Locations...),
		Permissions: append([]string(nil), signals.Permissions...),
		Values:      append([]string(nil), signals.Values...),
		EvidenceKV:  signals.EvidenceKV,
	}) {
		matches[item] = struct{}{}
	}
	if len(matches) > 1 {
		delete(matches, "built_in:customer_impacting")
	}

	out := make([]string, 0, len(matches))
	for item := range matches {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func addMatchSet(out map[string]struct{}, label string, set productiontargets.MatchSet, candidates []string) {
	for _, candidate := range candidates {
		normalized := normalizeToken(candidate)
		if normalized == "" {
			continue
		}
		if set.Match(normalized) {
			out[label+":"+normalized] = struct{}{}
		}
	}
}

func hasAnyPermission(permissions []string, allowed map[string]struct{}) bool {
	for _, permission := range permissions {
		if _, ok := allowed[normalizeToken(permission)]; ok {
			return true
		}
	}
	return false
}

func hasCredentialAccess(tool agginventory.Tool) bool {
	return hasCredentialAccessForSurface(tool.DataClass, tool.Permissions, nil)
}

func hasCredentialAccessForSurface(dataClass string, permissions []string, authSurfaces []string) bool {
	if normalizeToken(dataClass) == "credentials" {
		return true
	}
	for _, permission := range permissions {
		normalized := normalizeToken(permission)
		if strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "credential") ||
			strings.Contains(normalized, "oauth") ||
			strings.Contains(normalized, "oidc") ||
			normalized == "id-token.write" {
			return true
		}
	}
	for _, authSurface := range authSurfaces {
		normalized := normalizeToken(authSurface)
		if strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "credential") ||
			strings.HasSuffix(normalized, "_key") ||
			strings.Contains(normalized, "api_key") ||
			strings.Contains(normalized, "oauth") ||
			strings.Contains(normalized, "oidc") ||
			strings.Contains(normalized, "workload_identity") ||
			strings.Contains(normalized, "assume_role") ||
			strings.Contains(normalized, "sts") {
			return true
		}
	}
	return false
}

func hasExecPermission(permissions []string) bool {
	for _, permission := range permissions {
		if normalizeToken(permission) == "proc.exec" {
			return true
		}
	}
	return false
}

func hasExactPermission(permissions []string, target string) bool {
	target = normalizeToken(target)
	for _, permission := range permissions {
		if normalizeToken(permission) == target {
			return true
		}
	}
	return false
}

func deliveryChainStatus(pullRequestWrite, mergeExecute, deployWrite bool) string {
	switch {
	case pullRequestWrite && mergeExecute && deployWrite:
		return "pr_merge_deploy"
	case mergeExecute && deployWrite:
		return "merge_deploy"
	case pullRequestWrite && mergeExecute:
		return "pr_merge"
	case deployWrite:
		return "deploy_only"
	case pullRequestWrite:
		return "pr_only"
	case mergeExecute:
		return "merge_only"
	default:
		return "none"
	}
}

func currentProductionTargetStatus(productionConfigured bool) string {
	if productionConfigured {
		return agginventory.ProductionTargetsStatusConfigured
	}
	return agginventory.ProductionTargetsStatusNotConfigured
}

func mutableEndpointSemanticsFromSignals(signals findingSignals) []agginventory.MutableEndpointSemantic {
	values := []agginventory.MutableEndpointSemantic{}
	for _, raw := range signals.EvidenceKV["mutable_endpoint_semantic"] {
		parts := strings.SplitN(strings.TrimSpace(raw), "|", 4)
		if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		item := agginventory.MutableEndpointSemantic{
			Semantic: strings.TrimSpace(parts[0]),
		}
		if len(parts) > 1 {
			item.Confidence = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			item.Surface = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			item.Operation = strings.TrimSpace(parts[3])
		}
		if item.Operation != "" {
			item.EvidenceRefs = []string{item.Operation}
		}
		values = append(values, item)
	}
	return agginventory.NormalizeMutableEndpointSemantics(values)
}

func mergeMutableEndpointSemantics(groups ...[]agginventory.MutableEndpointSemantic) []agginventory.MutableEndpointSemantic {
	merged := []agginventory.MutableEndpointSemantic{}
	for _, group := range groups {
		merged = append(merged, agginventory.CloneMutableEndpointSemantics(group)...)
	}
	return agginventory.NormalizeMutableEndpointSemantics(merged)
}

func classifyCredentialProvenance(dataClass string, permissions []string, authSurfaces []string, signals findingSignals) *agginventory.CredentialProvenance {
	credentials := classifyCredentialProvenances(dataClass, permissions, authSurfaces, signals)
	if len(credentials) > 0 {
		return agginventory.CredentialRollup(credentials, nil)
	}
	return nil
}

func classifyCredentialAuthority(
	authSurfaces []string,
	signals findingSignals,
	credentialAccess bool,
	credentials []*agginventory.CredentialProvenance,
	provenance *agginventory.CredentialProvenance,
) *agginventory.CredentialAuthority {
	provenance = agginventory.CredentialRollup(credentials, provenance)
	normalizedProvenance := agginventory.NormalizeCredentialProvenance(provenance)
	workflowCredentialRefs := workflowCredentialSubjects(signals)
	referencedByWorkflow := len(workflowCredentialRefs) > 0 ||
		hasAnySignalValue(signals, "workflow_builtin_token", "github_token") ||
		firstSignalValue(signals, "credential_scope") == agginventory.CredentialScopeWorkflow ||
		(normalizedProvenance != nil && normalizedProvenance.Scope == agginventory.CredentialScopeWorkflow)
	present := normalizedProvenance != nil ||
		referencedByWorkflow ||
		hasAnySignalValue(signals, "identity_type", "github_app", "service_account", "bot_user") ||
		hasSecretLikeAuthSurface(authSurfaces)

	kind := agginventory.CredentialKindUnknown
	accessType := agginventory.CredentialAccessTypeUnknown
	confidence := "low"
	source := agginventory.CredentialSourceUnknown
	reasons := []string{}
	if normalizedProvenance != nil {
		kind = normalizedProvenance.CredentialKind
		accessType = normalizedProvenance.AccessType
		confidence = normalizedProvenance.Confidence
		reasons = append(reasons, normalizedProvenance.ClassificationReasons...)
		reasons = append(reasons, normalizedProvenance.EvidenceBasis...)
	}
	switch {
	case hasAnySignalValue(signals, "workflow_builtin_token", "github_token"):
		source = agginventory.CredentialSourceWorkflowBuiltin
	case len(workflowCredentialRefs) > 0:
		source = agginventory.CredentialSourceWorkflowSecretRef
	case hasAnySignalValue(signals, "identity_type", "github_app", "service_account", "bot_user"):
		source = agginventory.CredentialSourceNonHumanIdentity
	case hasSecretLikeAuthSurface(authSurfaces):
		source = agginventory.CredentialSourceAuthSurface
	case normalizedProvenance != nil:
		source = agginventory.CredentialSourceDetectorEvidence
	}

	rotationStatus := rotationEvidenceStatus(signals, normalizedProvenance, accessType, kind)
	if referencedByWorkflow {
		reasons = append(reasons, "credential_referenced_by_workflow:true")
	}
	if credentialAccess {
		reasons = append(reasons, "credential_usable_by_path:true")
	}
	if present {
		reasons = append(reasons, "credential_present:true")
	}

	authority := &agginventory.CredentialAuthority{
		CredentialPresent:              present,
		CredentialReferencedByWorkflow: referencedByWorkflow,
		CredentialUsableByPath:         credentialAccess && present,
		CredentialKind:                 kind,
		AccessType:                     accessType,
		StandingAccess:                 normalizedProvenance != nil && normalizedProvenance.StandingAccess,
		LikelyJIT:                      normalizedProvenance != nil && normalizedProvenance.LikelyJIT,
		RotationEvidenceStatus:         rotationStatus,
		CredentialSource:               source,
		Confidence:                     confidence,
		ReasonCodes:                    mergeSortedEvidence(reasons),
	}
	if normalizedProvenance == nil {
		authority.StandingAccess = accessType == agginventory.CredentialAccessTypeStanding || accessType == agginventory.CredentialAccessTypeInherited
		authority.LikelyJIT = accessType == agginventory.CredentialAccessTypeJIT || accessType == agginventory.CredentialAccessTypeWorkload
	}
	return decorateCredentialAuthority(authority, normalizedProvenance, authSurfaces, signals)
}

func rotationEvidenceStatus(signals findingSignals, provenance *agginventory.CredentialProvenance, accessType string, credentialKind string) string {
	switch strings.TrimSpace(firstSignalValue(signals, "rotation_evidence_status")) {
	case agginventory.CredentialRotationEvidencePresent,
		agginventory.CredentialRotationEvidenceMissing,
		agginventory.CredentialRotationEvidenceNotApplicable,
		agginventory.CredentialRotationEvidenceUnknown,
		agginventory.CredentialRotationEvidenceStale:
		return strings.TrimSpace(firstSignalValue(signals, "rotation_evidence_status"))
	}
	if hasAnySignalValue(signals, "rotation_evidence", "present") {
		return agginventory.CredentialRotationEvidencePresent
	}
	if hasAnySignalValue(signals, "rotation_evidence", "stale") {
		return agginventory.CredentialRotationEvidenceStale
	}
	if provenance != nil {
		return agginventory.NormalizeCredentialAuthority(&agginventory.CredentialAuthority{
			CredentialKind:         provenance.CredentialKind,
			AccessType:             provenance.AccessType,
			RotationEvidenceStatus: "",
		}).RotationEvidenceStatus
	}
	return agginventory.NormalizeCredentialAuthority(&agginventory.CredentialAuthority{
		CredentialKind:         credentialKind,
		AccessType:             accessType,
		RotationEvidenceStatus: "",
	}).RotationEvidenceStatus
}

func classifyCredentialProvenances(dataClass string, permissions []string, authSurfaces []string, signals findingSignals) []*agginventory.CredentialProvenance {
	candidates := []*agginventory.CredentialProvenance{}
	if builtin := workflowBuiltInTokenProvenance(permissions, signals); builtin != nil {
		candidates = append(candidates, builtin)
	}

	scope := inferredCredentialScope(signals, authSurfaces)
	evidenceLocation := credentialEvidenceLocation(signals)
	for _, subject := range credentialSignalSubjects(signals.EvidenceKV["credential_keys"]) {
		if candidate := credentialCandidateForSubject(subject, scope, []string{"credential_keys"}, authSurfaces, permissions, evidenceLocation, signals); candidate != nil {
			candidates = append(candidates, candidate)
		}
	}
	for _, subject := range workflowCredentialSubjects(signals) {
		if candidate := credentialCandidateForSubject(subject, agginventory.CredentialScopeWorkflow, []string{"workflow_secret_refs", "repo_workflow_secret_correlation"}, authSurfaces, permissions, evidenceLocation, signals); candidate != nil {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) > 0 {
		return agginventory.NormalizeCredentialProvenances(candidates)
	}
	if direct := directCredentialProvenance(signals); direct != nil {
		return agginventory.NormalizeCredentialProvenances([]*agginventory.CredentialProvenance{direct})
	}
	if hasOnlyNoncredentialWorkflowSecretRefs(signals) && !hasIndependentCredentialFallbackSignal(permissions, authSurfaces, signals) {
		return nil
	}
	if !hasCredentialAccessForSurface(dataClass, permissions, authSurfaces) {
		return nil
	}
	if fallback := fallbackCredentialProvenance(scope, evidenceLocation, permissions, authSurfaces, signals); fallback != nil {
		return agginventory.NormalizeCredentialProvenances([]*agginventory.CredentialProvenance{fallback})
	}
	return nil
}

func credentialCandidateForSubject(subject string, scope string, evidenceBasis []string, authSurfaces []string, permissions []string, evidenceLocation string, signals findingSignals) *agginventory.CredentialProvenance {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil
	}
	kind, accessType, reasons := classifyCredentialKind(subject, authSurfaces, permissions, signals)
	if typedKind, ok := typedCredentialKind(signals, subject); ok {
		kind = typedKind
		accessType = credentialAccessTypeForKind(kind)
		reasons = mergeSortedEvidence(
			credentialClassificationContextReasons(reasons),
			[]string{"detector:workflow_credential_kind", typedCredentialKindReason(kind)},
		)
		evidenceBasis = append(evidenceBasis, "workflow_credential_kind")
	}
	return decorateCredentialProvenance(&agginventory.CredentialProvenance{
		Type:                  credentialProvenanceTypeFor(kind, accessType),
		Subject:               subject,
		Scope:                 scope,
		Confidence:            "high",
		EvidenceBasis:         evidenceBasis,
		CredentialKind:        kind,
		AccessType:            accessType,
		EvidenceLocation:      evidenceLocation,
		ClassificationReasons: reasons,
	}, authSurfaces, signals)
}

func credentialClassificationContextReasons(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		normalized := strings.TrimSpace(reason)
		if normalized == "" || strings.HasPrefix(normalized, "subject:") || strings.HasPrefix(normalized, "fallback:") {
			continue
		}
		out = append(out, normalized)
	}
	return dedupeSorted(out)
}

func typedCredentialKindReason(kind string) string {
	switch strings.TrimSpace(kind) {
	case agginventory.CredentialKindGitHubWorkflowToken:
		return "subject:github_workflow_token"
	case agginventory.CredentialKindGitHubAppKey:
		return "subject:github_app_private_key"
	case agginventory.CredentialKindGitHubPAT:
		return "subject:github_pat"
	case agginventory.CredentialKindDeployKey:
		return "subject:deploy_key"
	case agginventory.CredentialKindCloudAdminKey:
		return "subject:cloud_admin_key"
	case agginventory.CredentialKindCloudAccessKey:
		return "subject:cloud_access_key"
	case agginventory.CredentialKindOIDCWorkloadID:
		return "subject:oidc_workload_identity"
	case agginventory.CredentialKindDelegatedOAuth:
		return "subject:oauth"
	case agginventory.CredentialKindInheritedHuman:
		return "subject:inherited_human"
	case agginventory.CredentialKindStaticSecret:
		return "subject:static_secret"
	case agginventory.CredentialKindUnknownDurable:
		return "fallback:unknown_durable"
	default:
		return "subject:" + firstNonEmptyString(strings.TrimSpace(kind), "unknown")
	}
}

func credentialSignalSubjects(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := []string{}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return dedupeSorted(out)
}

func workflowCredentialSubjects(signals findingSignals) []string {
	subjects := credentialSignalSubjects(signals.EvidenceKV["workflow_secret_refs"])
	excluded := credentialSignalSubjects(signals.EvidenceKV["workflow_noncredential_secret_refs"])
	if len(subjects) == 0 || len(excluded) == 0 {
		return subjects
	}
	excludedSet := make(map[string]struct{}, len(excluded))
	for _, subject := range excluded {
		excludedSet[subject] = struct{}{}
	}
	out := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		if _, skip := excludedSet[subject]; !skip {
			out = append(out, subject)
		}
	}
	return out
}

func hasOnlyNoncredentialWorkflowSecretRefs(signals findingSignals) bool {
	return len(credentialSignalSubjects(signals.EvidenceKV["workflow_secret_refs"])) > 0 &&
		len(workflowCredentialSubjects(signals)) == 0
}

func hasIndependentCredentialFallbackSignal(permissions, authSurfaces []string, signals findingSignals) bool {
	if hasAnySignalValue(signals, "identity_type", "service_account", "github_app", "bot_user") {
		return true
	}
	for _, permission := range permissions {
		normalized := normalizeToken(permission)
		if normalized == "id-token.write" ||
			strings.Contains(normalized, "oauth") ||
			strings.Contains(normalized, "oidc") ||
			strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "credential") {
			return true
		}
	}
	return hasCredentialAccessForSurface("", nil, authSurfaces)
}

func workflowBuiltInTokenProvenance(permissions []string, signals findingSignals) *agginventory.CredentialProvenance {
	if !hasAnySignalValue(signals, "workflow_builtin_token", "github_token") {
		return nil
	}
	reasons := []string{"builtin:github_token"}
	evidenceBasis := []string{"workflow_builtin_token"}
	for _, posture := range dedupeSorted(signals.EvidenceKV["workflow_token_permission"]) {
		reasons = append(reasons, "permission:"+posture)
		evidenceBasis = append(evidenceBasis, "workflow_token_permission:"+posture)
	}
	riskMultiplier := 1.03
	for _, posture := range signals.EvidenceKV["workflow_token_permission"] {
		if strings.HasSuffix(strings.TrimSpace(posture), "=write") || strings.TrimSpace(posture) == "write-all" {
			riskMultiplier = 1.08
			break
		}
	}
	return decorateCredentialProvenance(&agginventory.CredentialProvenance{
		Type:                  agginventory.CredentialProvenanceJIT,
		Subject:               "GITHUB_TOKEN",
		Scope:                 agginventory.CredentialScopeWorkflow,
		Confidence:            "high",
		EvidenceBasis:         mergeSortedEvidence(evidenceBasis),
		CredentialKind:        agginventory.CredentialKindGitHubWorkflowToken,
		AccessType:            agginventory.CredentialAccessTypeJIT,
		EvidenceLocation:      credentialEvidenceLocation(signals),
		ClassificationReasons: mergeSortedEvidence(reasons),
		RiskMultiplier:        riskMultiplier,
	}, nil, signals)
}

func fallbackCredentialProvenance(scope string, evidenceLocation string, permissions []string, authSurfaces []string, signals findingSignals) *agginventory.CredentialProvenance {
	switch {
	case hasAnySignalValue(signals, "identity_type", "service_account", "github_app"):
		subject := firstSignalValue(signals, "subject")
		kind := agginventory.CredentialKindOIDCWorkloadID
		accessType := agginventory.CredentialAccessTypeWorkload
		reasons := []string{"identity_type:" + firstSignalValue(signals, "identity_type")}
		if strings.Contains(normalizeToken(subject), "github_app") {
			kind = agginventory.CredentialKindGitHubAppKey
			accessType = agginventory.CredentialAccessTypeStanding
			reasons = append(reasons, "subject:"+subject)
		}
		return decorateCredentialProvenance(&agginventory.CredentialProvenance{
			Type:                  credentialProvenanceTypeFor(kind, accessType),
			Subject:               subject,
			Scope:                 agginventory.CredentialScopeWorkflow,
			Confidence:            "high",
			EvidenceBasis:         []string{"identity_type"},
			CredentialKind:        kind,
			AccessType:            accessType,
			EvidenceLocation:      evidenceLocation,
			ClassificationReasons: reasons,
		}, authSurfaces, signals)
	case hasAnySignalValue(signals, "identity_type", "bot_user") || hasAnyAuthSurface(authSurfaces, "github_actor", "user_token", "personal_access_token", "pat"):
		subject := firstNonEmptyString(firstSignalValue(signals, "subject"), firstMatchingAuthSurface(authSurfaces, "github_actor", "user_token", "personal_access_token", "pat"))
		kind := agginventory.CredentialKindInheritedHuman
		if hasAnyAuthSurface(authSurfaces, "personal_access_token", "pat", "github_token") {
			kind = agginventory.CredentialKindGitHubPAT
		}
		return decorateCredentialProvenance(&agginventory.CredentialProvenance{
			Type:                  credentialProvenanceTypeFor(kind, agginventory.CredentialAccessTypeInherited),
			Subject:               subject,
			Scope:                 scope,
			Confidence:            "medium",
			EvidenceBasis:         mergeSortedEvidence([]string{"identity_type"}, authSurfaces),
			CredentialKind:        kind,
			AccessType:            agginventory.CredentialAccessTypeInherited,
			EvidenceLocation:      evidenceLocation,
			ClassificationReasons: mergeSortedEvidence([]string{"identity_type:bot_user"}, authSurfaceEvidenceBasis(authSurfaces, "github_actor", "user_token", "personal_access_token", "pat")),
		}, authSurfaces, signals)
	case hasAnyAuthSurface(authSurfaces, "oauth", "oauth2"):
		return decorateCredentialProvenance(&agginventory.CredentialProvenance{
			Type:                  agginventory.CredentialProvenanceOAuthDelegation,
			Subject:               firstMatchingAuthSurface(authSurfaces, "oauth", "oauth2"),
			Scope:                 agginventory.CredentialScopeTool,
			Confidence:            "high",
			EvidenceBasis:         authSurfaceEvidenceBasis(authSurfaces, "oauth", "oauth2"),
			CredentialKind:        agginventory.CredentialKindDelegatedOAuth,
			AccessType:            agginventory.CredentialAccessTypeDelegated,
			EvidenceLocation:      evidenceLocation,
			ClassificationReasons: []string{"auth_surface:oauth"},
		}, authSurfaces, signals)
	case hasAnyPermission(permissions, map[string]struct{}{"id-token.write": {}}) || hasAnyAuthSurface(authSurfaces, "oidc", "workload_identity", "sts", "assume_role"):
		kind := agginventory.CredentialKindOIDCWorkloadID
		accessType := agginventory.CredentialAccessTypeWorkload
		reasons := mergeSortedEvidence([]string{"permission:id-token.write"}, authSurfaceEvidenceBasis(authSurfaces, "oidc", "workload_identity", "sts", "assume_role"))
		if boolSignalState(signals.EvidenceKV["human_gate"]) == "true" || strings.Contains(stringSignalState(signals.EvidenceKV["approval_source"], ""), "manual") {
			kind = agginventory.CredentialKindJITCredential
			accessType = agginventory.CredentialAccessTypeJIT
			reasons = append(reasons, "gate:jit_evidence")
		}
		return decorateCredentialProvenance(&agginventory.CredentialProvenance{
			Type:                  credentialProvenanceTypeFor(kind, accessType),
			Subject:               firstNonEmptyString(firstMatchingAuthSurface(authSurfaces, "oidc", "workload_identity", "sts", "assume_role"), "id-token.write"),
			Scope:                 agginventory.CredentialScopeWorkflow,
			Confidence:            "high",
			EvidenceBasis:         mergeSortedEvidence([]string{"id-token.write"}, authSurfaces),
			CredentialKind:        kind,
			AccessType:            accessType,
			EvidenceLocation:      evidenceLocation,
			ClassificationReasons: reasons,
		}, authSurfaces, signals)
	case hasSecretLikeAuthSurface(authSurfaces):
		subject := firstMatchingSecretAuthSurface(authSurfaces)
		kind, accessType, reasons := classifyCredentialKind(subject, authSurfaces, permissions, signals)
		return decorateCredentialProvenance(&agginventory.CredentialProvenance{
			Type:                  credentialProvenanceTypeFor(kind, accessType),
			Subject:               subject,
			Scope:                 scope,
			Confidence:            "medium",
			EvidenceBasis:         authSurfaceEvidenceBasis(authSurfaces),
			CredentialKind:        kind,
			AccessType:            accessType,
			EvidenceLocation:      evidenceLocation,
			ClassificationReasons: reasons,
		}, authSurfaces, signals)
	default:
		return decorateCredentialProvenance(&agginventory.CredentialProvenance{
			Type:                  agginventory.CredentialProvenanceUnknown,
			Scope:                 agginventory.CredentialScopeUnknown,
			Confidence:            "low",
			EvidenceBasis:         mergeSortedEvidence([]string{"credential_access"}, authSurfaces),
			CredentialKind:        agginventory.CredentialKindUnknownDurable,
			AccessType:            agginventory.CredentialAccessTypeStanding,
			EvidenceLocation:      evidenceLocation,
			ClassificationReasons: []string{"fallback:unknown_durable"},
		}, authSurfaces, signals)
	}
}

func directCredentialProvenance(signals findingSignals) *agginventory.CredentialProvenance {
	types := dedupeSorted(signals.EvidenceKV["credential_provenance_type"])
	if len(types) == 0 {
		return nil
	}
	subjects := dedupeSorted(signals.EvidenceKV["credential_subject"])
	scopes := dedupeSorted(signals.EvidenceKV["credential_scope"])
	confidences := dedupeSorted(signals.EvidenceKV["credential_confidence"])
	if len(types) > 1 || len(subjects) > 1 || len(scopes) > 1 {
		return decorateCredentialProvenance(&agginventory.CredentialProvenance{
			Type:             agginventory.CredentialProvenanceUnknown,
			Scope:            agginventory.CredentialScopeUnknown,
			Confidence:       "low",
			CredentialKind:   agginventory.CredentialKindUnknownDurable,
			AccessType:       agginventory.CredentialAccessTypeStanding,
			EvidenceLocation: credentialEvidenceLocation(signals),
			EvidenceBasis: mergeSortedEvidence(
				[]string{"credential_provenance_conflict"},
				prefixedEvidence("credential_provenance_type", types),
				prefixedEvidence("credential_subject", subjects),
				prefixedEvidence("credential_scope", scopes),
			),
			ClassificationReasons: []string{"direct:conflict"},
		}, nil, signals)
	}
	confidence := "low"
	if len(confidences) == 1 {
		confidence = confidences[0]
	}
	subject := ""
	if len(subjects) == 1 {
		subject = subjects[0]
	}
	scope := agginventory.CredentialScopeUnknown
	if len(scopes) == 1 {
		scope = scopes[0]
	}
	kind, accessType, reasons := classifyCredentialKind(subject, nil, nil, signals)
	return decorateCredentialProvenance(&agginventory.CredentialProvenance{
		Type:                  types[0],
		Subject:               subject,
		Scope:                 scope,
		Confidence:            confidence,
		EvidenceBasis:         mergeSortedEvidence([]string{"credential_provenance_type"}, signals.EvidenceKV["credential_subject"], signals.EvidenceKV["credential_scope"]),
		CredentialKind:        kind,
		AccessType:            accessType,
		EvidenceLocation:      credentialEvidenceLocation(signals),
		ClassificationReasons: reasons,
	}, nil, signals)
}

func credentialEvidenceLocation(signals findingSignals) string {
	if len(signals.Locations) == 0 {
		return ""
	}
	return strings.TrimSpace(signals.Locations[0])
}

func credentialProvenanceTypeFor(kind, accessType string) string {
	switch strings.TrimSpace(accessType) {
	case agginventory.CredentialAccessTypeWorkload:
		return agginventory.CredentialProvenanceWorkloadIdentity
	case agginventory.CredentialAccessTypeDelegated:
		return agginventory.CredentialProvenanceOAuthDelegation
	case agginventory.CredentialAccessTypeJIT:
		return agginventory.CredentialProvenanceJIT
	case agginventory.CredentialAccessTypeInherited:
		return agginventory.CredentialProvenanceInheritedHuman
	}
	switch strings.TrimSpace(kind) {
	case agginventory.CredentialKindInheritedHuman:
		return agginventory.CredentialProvenanceInheritedHuman
	case agginventory.CredentialKindGitHubWorkflowToken:
		return agginventory.CredentialProvenanceJIT
	case agginventory.CredentialKindDelegatedOAuth:
		return agginventory.CredentialProvenanceOAuthDelegation
	case agginventory.CredentialKindOIDCWorkloadID:
		return agginventory.CredentialProvenanceWorkloadIdentity
	case agginventory.CredentialKindJITCredential:
		return agginventory.CredentialProvenanceJIT
	case agginventory.CredentialKindUnknownDurable, agginventory.CredentialKindUnknown:
		return agginventory.CredentialProvenanceUnknown
	default:
		return agginventory.CredentialProvenanceStaticSecret
	}
}

func classifyCredentialKind(subject string, authSurfaces []string, permissions []string, signals findingSignals) (string, string, []string) {
	subjectText := normalizeToken(subject)
	if kind, accessType, reasons, ok := classifyCredentialKindFromText(subjectText, subject, signals); ok {
		return kind, accessType, mergeSortedEvidence(reasons)
	}

	candidates := append([]string(nil), authSurfaces...)
	candidates = append(candidates, signals.EvidenceKV["credential_subject"]...)
	if subjectText == "" {
		candidates = append(candidates, workflowCredentialSubjects(signals)...)
		candidates = append(candidates, signals.EvidenceKV["credential_keys"]...)
	}
	aggregateText := normalizeToken(strings.Join(candidates, ","))
	if kind, accessType, reasons, ok := classifyCredentialKindFromText(aggregateText, "", signals); ok {
		return kind, accessType, mergeSortedEvidence(reasons)
	}
	if kind, accessType, reasons, ok := classifyCredentialKindFromPermissions(permissions, signals); ok {
		return kind, accessType, mergeSortedEvidence(reasons)
	}
	if subjectText != "" || aggregateText != "" {
		reasons := []string{"subject:static_secret"}
		return agginventory.CredentialKindStaticSecret, agginventory.CredentialAccessTypeStanding, mergeSortedEvidence(reasons)
	}
	return agginventory.CredentialKindUnknownDurable, agginventory.CredentialAccessTypeStanding, []string{"fallback:unknown_durable"}
}

func classifyCredentialKindFromText(text string, subject string, signals findingSignals) (string, string, []string, bool) {
	text = normalizeToken(text)
	if text == "" {
		return "", "", nil, false
	}
	tokens := credentialIdentifierTokens(text)
	reasons := []string{}
	addReason := func(value string) {
		if strings.TrimSpace(value) != "" {
			reasons = append(reasons, strings.TrimSpace(value))
		}
	}

	switch {
	case hasAnySignalValue(signals, "workflow_builtin_token", "github_token") && normalizeToken(subject) == "github_token":
		reasons = append(reasons, "subject:github_workflow_token")
		reasons = append(reasons, prefixedEvidence("workflow_token_permission", signals.EvidenceKV["workflow_token_permission"])...)
		return agginventory.CredentialKindGitHubWorkflowToken, agginventory.CredentialAccessTypeJIT, reasons, true
	case containsAnyIdentifierToken(tokens, "github", "gh") && containsIdentifierToken(tokens, "app") && containsIdentifierToken(tokens, "key"):
		addReason("subject:github_app_private_key")
		return agginventory.CredentialKindGitHubAppKey, agginventory.CredentialAccessTypeStanding, reasons, true
	case containsAnyIdentifierToken(tokens, "deploy", "ssh") && containsIdentifierToken(tokens, "key"):
		addReason("subject:deploy_key")
		return agginventory.CredentialKindDeployKey, agginventory.CredentialAccessTypeStanding, reasons, true
	case hasCloudAdminSignal(text):
		addReason("subject:cloud_admin_key")
		return agginventory.CredentialKindCloudAdminKey, agginventory.CredentialAccessTypeStanding, reasons, true
	case hasCloudAccessSignal(text):
		addReason("subject:cloud_access_key")
		return agginventory.CredentialKindCloudAccessKey, agginventory.CredentialAccessTypeStanding, reasons, true
	case containsIdentifierToken(tokens, "pat") || containsIdentifierSequence(tokens, "personal", "access", "token"):
		addReason("subject:github_pat")
		return agginventory.CredentialKindGitHubPAT, agginventory.CredentialAccessTypeStanding, reasons, true
	case containsIdentifierToken(tokens, "oauth") || containsIdentifierToken(tokens, "oauth2"):
		addReason("subject:oauth")
		return agginventory.CredentialKindDelegatedOAuth, agginventory.CredentialAccessTypeDelegated, reasons, true
	case containsIdentifierToken(tokens, "oidc") || containsIdentifierSequence(tokens, "workload", "identity") || containsIdentifierSequence(tokens, "assume", "role") || containsIdentifierToken(tokens, "sts"):
		addReason("subject:oidc_workload_identity")
		if boolSignalState(signals.EvidenceKV["human_gate"]) == "true" || strings.Contains(stringSignalState(signals.EvidenceKV["approval_source"], ""), "manual") {
			addReason("gate:jit_evidence")
			return agginventory.CredentialKindJITCredential, agginventory.CredentialAccessTypeJIT, reasons, true
		}
		return agginventory.CredentialKindOIDCWorkloadID, agginventory.CredentialAccessTypeWorkload, reasons, true
	case containsIdentifierSequence(tokens, "github", "actor") || containsIdentifierSequence(tokens, "user", "token") || containsIdentifierSequence(tokens, "bot", "user"):
		addReason("subject:inherited_human")
		return agginventory.CredentialKindInheritedHuman, agginventory.CredentialAccessTypeInherited, reasons, true
	default:
		return "", "", nil, false
	}
}

func classifyCredentialKindFromPermissions(permissions []string, signals findingSignals) (string, string, []string, bool) {
	if !hasAnyPermission(permissions, map[string]struct{}{"id-token.write": {}}) {
		return "", "", nil, false
	}
	reasons := []string{"permission:id-token.write"}
	if boolSignalState(signals.EvidenceKV["human_gate"]) == "true" || strings.Contains(stringSignalState(signals.EvidenceKV["approval_source"], ""), "manual") {
		reasons = append(reasons, "gate:jit_evidence")
		return agginventory.CredentialKindJITCredential, agginventory.CredentialAccessTypeJIT, reasons, true
	}
	return agginventory.CredentialKindOIDCWorkloadID, agginventory.CredentialAccessTypeWorkload, reasons, true
}

func hasCloudAdminSignal(value string) bool {
	tokens := credentialIdentifierTokens(value)
	return containsAnyIdentifierToken(tokens, "aws", "gcp", "azure", "cloud") &&
		containsAnyIdentifierToken(tokens, "admin", "root", "owner")
}

func hasCloudAccessSignal(value string) bool {
	tokens := credentialIdentifierTokens(value)
	return containsAnyIdentifierToken(tokens, "aws", "gcp", "azure", "cloud") &&
		(containsIdentifierSequence(tokens, "access", "key") ||
			containsIdentifierSequence(tokens, "secret", "key") ||
			containsIdentifierSequence(tokens, "service", "account") ||
			containsAnyIdentifierToken(tokens, "credential", "credentials"))
}

func typedCredentialKind(signals findingSignals, subject string) (string, bool) {
	subject = normalizeToken(subject)
	for _, raw := range signals.EvidenceKV["workflow_credential_kind"] {
		parts := strings.SplitN(strings.TrimSpace(raw), "|", 2)
		if len(parts) != 2 || normalizeToken(parts[0]) != subject {
			continue
		}
		kind := normalizeToken(parts[1])
		switch kind {
		case agginventory.CredentialKindGitHubPAT,
			agginventory.CredentialKindGitHubWorkflowToken,
			agginventory.CredentialKindGitHubAppKey,
			agginventory.CredentialKindDeployKey,
			agginventory.CredentialKindCloudAdminKey,
			agginventory.CredentialKindCloudAccessKey,
			agginventory.CredentialKindOIDCWorkloadID,
			agginventory.CredentialKindDelegatedOAuth,
			agginventory.CredentialKindJITCredential,
			agginventory.CredentialKindInheritedHuman,
			agginventory.CredentialKindStaticSecret,
			agginventory.CredentialKindUnknownDurable,
			agginventory.CredentialKindUnknown:
			return kind, true
		}
	}
	return "", false
}

func credentialAccessTypeForKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case agginventory.CredentialKindGitHubWorkflowToken, agginventory.CredentialKindJITCredential:
		return agginventory.CredentialAccessTypeJIT
	case agginventory.CredentialKindOIDCWorkloadID:
		return agginventory.CredentialAccessTypeWorkload
	case agginventory.CredentialKindDelegatedOAuth:
		return agginventory.CredentialAccessTypeDelegated
	case agginventory.CredentialKindInheritedHuman:
		return agginventory.CredentialAccessTypeInherited
	default:
		return agginventory.CredentialAccessTypeStanding
	}
}

func credentialIdentifierTokens(value string) []string {
	return strings.FieldsFunc(strings.ToLower(strings.TrimSpace(value)), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

func containsAnyIdentifierToken(tokens []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if containsIdentifierToken(tokens, candidate) {
			return true
		}
	}
	return false
}

func containsIdentifierToken(tokens []string, candidate string) bool {
	for _, token := range tokens {
		if token == candidate {
			return true
		}
	}
	return false
}

func containsIdentifierSequence(tokens []string, sequence ...string) bool {
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

func inferredCredentialScope(signals findingSignals, authSurfaces []string) string {
	if scope := firstSignalValue(signals, "credential_scope"); scope != "" {
		return scope
	}
	for _, location := range signals.Locations {
		lower := normalizeToken(location)
		switch {
		case strings.Contains(lower, ".github/workflows"),
			strings.Contains(lower, ".gitlab-ci.yml"),
			strings.Contains(lower, ".gitlab-ci.yaml"),
			strings.Contains(lower, ".gitlab/ci/"),
			strings.Contains(lower, "azure-pipelines.yml"),
			strings.Contains(lower, "azure-pipelines.yaml"),
			strings.Contains(lower, ".azure/pipelines/"),
			lower == "jenkinsfile":
			return agginventory.CredentialScopeWorkflow
		case strings.HasPrefix(lower, ".env"):
			return agginventory.CredentialScopeEnvironment
		}
	}
	if len(authSurfaces) > 0 {
		return agginventory.CredentialScopeTool
	}
	if len(signals.Repos) > 1 {
		return agginventory.CredentialScopeOrg
	}
	return agginventory.CredentialScopeRepository
}

func hasAnySignalValue(signals findingSignals, key string, candidates ...string) bool {
	values := signals.EvidenceKV[normalizeToken(key)]
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		normalized := normalizeToken(value)
		for _, candidate := range candidates {
			if normalized == normalizeToken(candidate) {
				return true
			}
		}
	}
	return false
}

func firstSignalValue(signals findingSignals, key string) string {
	values := signals.EvidenceKV[normalizeToken(key)]
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func hasAnyAuthSurface(authSurfaces []string, needles ...string) bool {
	return firstMatchingAuthSurface(authSurfaces, needles...) != ""
}

func firstMatchingAuthSurface(authSurfaces []string, needles ...string) string {
	for _, surface := range authSurfaces {
		normalized := normalizeToken(surface)
		for _, needle := range needles {
			if strings.Contains(normalized, normalizeToken(needle)) {
				return strings.TrimSpace(surface)
			}
		}
	}
	return ""
}

func hasSecretLikeAuthSurface(authSurfaces []string) bool {
	return firstMatchingSecretAuthSurface(authSurfaces) != ""
}

func firstMatchingSecretAuthSurface(authSurfaces []string) string {
	for _, surface := range authSurfaces {
		normalized := normalizeToken(surface)
		if strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "credential") ||
			strings.HasSuffix(normalized, "_key") ||
			strings.Contains(normalized, "api_key") {
			return strings.TrimSpace(surface)
		}
	}
	return ""
}

func authSurfaceEvidenceBasis(authSurfaces []string, needles ...string) []string {
	out := make([]string, 0, len(authSurfaces))
	for _, surface := range authSurfaces {
		if len(needles) == 0 || firstMatchingAuthSurface([]string{surface}, needles...) != "" {
			out = append(out, "auth_surface:"+strings.TrimSpace(surface))
		}
	}
	return dedupeSorted(out)
}

func mergeSortedEvidence(groups ...[]string) []string {
	out := make([]string, 0)
	for _, group := range groups {
		for _, value := range group {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			out = append(out, trimmed)
		}
	}
	return dedupeSorted(out)
}

func prefixedEvidence(prefix string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, strings.TrimSpace(prefix)+":"+trimmed)
	}
	return dedupeSorted(out)
}

func resolveOperationalOwner(tool agginventory.Tool, repos []string, location string, org string) owners.Resolution {
	candidates := map[string]ownershipCandidate{}
	trimmedLocation := strings.TrimSpace(location)
	for _, item := range tool.Locations {
		if trimmedLocation != "" && strings.TrimSpace(item.Location) != trimmedLocation {
			continue
		}
		if len(repos) > 0 && !containsString(repos, item.Repo) {
			continue
		}
		key := strings.Join([]string{
			strings.TrimSpace(item.Owner),
			strings.TrimSpace(item.OwnerSource),
			strings.TrimSpace(item.OwnershipStatus),
			strings.TrimSpace(item.OwnershipState),
		}, "|")
		state := strings.TrimSpace(item.OwnershipState)
		if state == "" {
			state = fallbackOwnershipState(strings.TrimSpace(item.OwnershipStatus))
			if strings.TrimSpace(item.OwnerSource) == owners.OwnerSourceConflict {
				state = owners.OwnershipStateConflicting
			}
		}
		confidence := item.OwnershipConfidence
		if confidence == 0 && strings.TrimSpace(item.OwnershipStatus) != owners.OwnershipStatusUnresolved {
			confidence = fallbackOwnershipConfidence(strings.TrimSpace(item.OwnershipStatus))
		}
		evidence := cloneStringSlice(item.OwnershipEvidence)
		if len(evidence) == 0 && strings.TrimSpace(item.OwnerSource) != "" {
			evidence = []string{strings.TrimSpace(item.OwnerSource)}
		}
		conflicts := cloneStringSlice(item.OwnershipConflicts)
		candidates[key] = ownershipCandidate{
			owner:               strings.TrimSpace(item.Owner),
			ownerSource:         strings.TrimSpace(item.OwnerSource),
			ownershipStatus:     strings.TrimSpace(item.OwnershipStatus),
			ownershipState:      state,
			ownershipConfidence: confidence,
			ownershipEvidence:   evidence,
			ownershipConflicts:  conflicts,
			ownershipDecision:   cloneEvidenceDecision(item.OwnershipDecision),
		}
	}
	if len(candidates) == 0 {
		return fallbackOperationalOwner(repos, org)
	}

	ownerSet := map[string]ownershipCandidate{}
	for _, item := range candidates {
		current, exists := ownerSet[item.owner]
		if !exists || ownershipPriority(item.ownershipStatus) < ownershipPriority(current.ownershipStatus) {
			ownerSet[item.owner] = item
		}
	}
	explicitOwners := filterOwnershipCandidates(ownerSet, owners.OwnershipStatusExplicit)
	if len(explicitOwners) == 1 {
		for _, item := range explicitOwners {
			return owners.Resolution{
				Owner:               item.owner,
				OwnerSource:         item.ownerSource,
				OwnershipStatus:     item.ownershipStatus,
				OwnershipState:      item.ownershipState,
				OwnershipConfidence: item.ownershipConfidence,
				EvidenceBasis:       cloneStringSlice(item.ownershipEvidence),
				ConflictOwners:      cloneStringSlice(item.ownershipConflicts),
				EvidenceDecision:    cloneEvidenceDecision(item.ownershipDecision),
			}
		}
	}
	if len(explicitOwners) > 1 {
		fallback := fallbackOperationalOwner(repos, org)
		fallback.OwnerSource = owners.OwnerSourceConflict
		fallback.OwnershipStatus = owners.OwnershipStatusUnresolved
		fallback.OwnershipState = owners.OwnershipStateConflicting
		fallback.OwnershipConfidence = 0.2
		fallback.ConflictOwners = sortedOwnerCandidates(ownerSet)
		fallback.EvidenceBasis = mergeOwnershipEvidence(ownerSet)
		return fallback
	}
	if len(ownerSet) == 1 {
		for _, item := range ownerSet {
			return owners.Resolution{
				Owner:               item.owner,
				OwnerSource:         item.ownerSource,
				OwnershipStatus:     item.ownershipStatus,
				OwnershipState:      item.ownershipState,
				OwnershipConfidence: item.ownershipConfidence,
				EvidenceBasis:       cloneStringSlice(item.ownershipEvidence),
				ConflictOwners:      cloneStringSlice(item.ownershipConflicts),
				EvidenceDecision:    cloneEvidenceDecision(item.ownershipDecision),
			}
		}
	}

	fallback := fallbackOperationalOwner(repos, org)
	fallback.OwnerSource = owners.OwnerSourceConflict
	fallback.OwnershipStatus = owners.OwnershipStatusUnresolved
	fallback.OwnershipState = owners.OwnershipStateConflicting
	fallback.OwnershipConfidence = 0.2
	fallback.ConflictOwners = sortedOwnerCandidates(ownerSet)
	fallback.EvidenceBasis = mergeOwnershipEvidence(ownerSet)
	return fallback
}

func filterOwnershipCandidates(candidates map[string]ownershipCandidate, status string) map[string]ownershipCandidate {
	filtered := map[string]ownershipCandidate{}
	for key, item := range candidates {
		if strings.TrimSpace(item.ownershipStatus) == strings.TrimSpace(status) {
			filtered[key] = item
		}
	}
	return filtered
}

func fallbackOperationalOwner(repos []string, org string) owners.Resolution {
	repo := ""
	if len(repos) > 0 {
		sortedRepos := append([]string(nil), repos...)
		sort.Strings(sortedRepos)
		repo = strings.TrimSpace(sortedRepos[0])
	}
	status := owners.OwnershipStatusInferred
	if repo == "" {
		status = owners.OwnershipStatusUnresolved
	}
	return owners.Resolution{
		Owner:               owners.FallbackOwner(repo, org),
		OwnerSource:         owners.OwnerSourceRepoFallback,
		OwnershipStatus:     status,
		OwnershipState:      fallbackOwnershipState(status),
		OwnershipConfidence: fallbackOwnershipConfidence(status),
		EvidenceBasis:       []string{"repo_fallback:repo_name"},
	}
}

func sortedOwnerCandidates(candidates map[string]ownershipCandidate) []string {
	ownersOut := make([]string, 0, len(candidates))
	for owner := range candidates {
		if strings.TrimSpace(owner) != "" {
			ownersOut = append(ownersOut, strings.TrimSpace(owner))
		}
	}
	sort.Strings(ownersOut)
	return ownersOut
}

func mergeOwnershipEvidence(candidates map[string]ownershipCandidate) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, item := range candidates {
		for _, evidence := range item.ownershipEvidence {
			trimmed := strings.TrimSpace(evidence)
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}

func fallbackOwnershipState(status string) string {
	switch strings.TrimSpace(status) {
	case owners.OwnershipStatusExplicit:
		return owners.OwnershipStateExplicit
	case owners.OwnershipStatusUnresolved:
		return owners.OwnershipStateMissing
	default:
		return owners.OwnershipStateInferred
	}
}

func fallbackOwnershipConfidence(status string) float64 {
	switch strings.TrimSpace(status) {
	case owners.OwnershipStatusExplicit:
		return 0.9
	case owners.OwnershipStatusUnresolved:
		return 0
	default:
		return 0.45
	}
}

func primaryLocation(tool agginventory.Tool) string {
	if len(tool.Locations) == 0 {
		return ""
	}
	locations := append([]agginventory.ToolLocation(nil), tool.Locations...)
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].Repo != locations[j].Repo {
			return locations[i].Repo < locations[j].Repo
		}
		return locations[i].Location < locations[j].Location
	})
	return strings.TrimSpace(locations[0].Location)
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func ownershipPriority(status string) int {
	switch strings.TrimSpace(status) {
	case owners.OwnershipStatusExplicit:
		return 0
	case owners.OwnershipStatusInferred:
		return 1
	default:
		return 2
	}
}

func approvalGapReasons(signals findingSignals, permissions []string, deploymentStatus string) []string {
	reasons := []string{}
	hasDeliveryPath := hasWriteLikePermission(permissions) ||
		hasExactPermission(permissions, "pull_request.write") ||
		hasExactPermission(permissions, "merge.execute") ||
		hasExactPermission(permissions, "deploy.write") ||
		strings.TrimSpace(deploymentStatus) == "deployed" ||
		boolSignalState(signals.EvidenceKV["auto_deploy"]) == "true"
	if !hasDeliveryPath {
		return nil
	}

	switch stringSignalState(signals.EvidenceKV["approval_source"], "missing") {
	case "missing":
		reasons = append(reasons, "approval_source_missing")
	case "ambiguous":
		reasons = append(reasons, "approval_source_ambiguous")
	}

	switch stringSignalState(signals.EvidenceKV["deployment_gate"], "missing") {
	case "missing":
		reasons = append(reasons, "deployment_gate_missing")
	case "open":
		reasons = append(reasons, "deployment_gate_open")
	case "ambiguous":
		reasons = append(reasons, "deployment_gate_ambiguous")
	}

	if boolSignalState(signals.EvidenceKV["auto_deploy"]) == "true" {
		switch boolSignalState(signals.EvidenceKV["human_gate"]) {
		case "missing":
			reasons = append(reasons, "human_gate_missing")
		case "false":
			reasons = append(reasons, "auto_deploy_without_human_gate")
		case "mixed":
			reasons = append(reasons, "human_gate_ambiguous")
		}
	}

	switch stringSignalState(signals.EvidenceKV["proof_requirement"], "missing") {
	case "missing":
		reasons = append(reasons, "proof_requirement_missing")
	case "ambiguous":
		reasons = append(reasons, "proof_requirement_ambiguous")
	}

	if len(reasons) == 0 {
		return nil
	}
	return dedupeSortedPreserveCase(reasons)
}

func workflowTriggerClass(
	signals findingSignals,
	permissions []string,
	deploymentStatus string,
	deployWrite bool,
	productionWrite bool,
) string {
	if productionWrite || deployWrite || hasExactPermission(permissions, "deploy.write") || strings.TrimSpace(deploymentStatus) == "deployed" {
		return "deploy_pipeline"
	}
	triggers := splitNormalizedSignalValues(signals.EvidenceKV["workflow_triggers"])
	switch {
	case containsNormalizedValue(triggers, "schedule"):
		return "scheduled"
	case containsNormalizedValue(triggers, "workflow_dispatch"):
		return "workflow_dispatch"
	default:
		return ""
	}
}

func deliveryHarnesses(signals findingSignals, toolType string, location string) []string {
	values := splitNormalizedSignalValues(signals.EvidenceKV["delivery_harness"])
	if len(values) > 0 {
		return values
	}
	switch normalizeToken(toolType) {
	case "codex":
		return []string{"codex_cli"}
	case "claude":
		return []string{"claude_code"}
	case "cursor":
		return []string{"cursor_rules"}
	case "ci_agent":
		return []string{"ci_workflow"}
	case "compiled_action":
		return []string{"compiled_action"}
	}
	if strings.Contains(normalizeToken(location), ".github/workflows") {
		return []string{"ci_workflow"}
	}
	return nil
}

func resolverRefs(signals findingSignals, fallbackLocation string) []string {
	values := splitNormalizedSignalValues(signals.EvidenceKV["resolver_ref"])
	if len(values) > 0 {
		return values
	}
	if trimmed := strings.TrimSpace(fallbackLocation); strings.HasSuffix(strings.ToLower(trimmed), "agents.md") || strings.HasSuffix(strings.ToLower(trimmed), "claude.md") || strings.Contains(strings.ToLower(trimmed), ".cursor/rules/") {
		return []string{trimmed}
	}
	return nil
}

func evalConfigRefs(signals findingSignals, fallbackLocation string) []string {
	values := splitNormalizedSignalValues(signals.EvidenceKV["eval_config_ref"])
	if len(values) > 0 {
		return values
	}
	if strings.Contains(firstSignalValue(signals, "tool_sequence"), "gait.eval.script") && strings.TrimSpace(fallbackLocation) != "" {
		return []string{strings.TrimSpace(fallbackLocation)}
	}
	return nil
}

func dryRunRequired(signals findingSignals) bool {
	return boolSignalState(signals.EvidenceKV["dry_run_required"]) == "true"
}

func sandboxGates(signals findingSignals) []string {
	return splitNormalizedSignalValues(signals.EvidenceKV["sandbox_gate"])
}

func testGates(signals findingSignals) []string {
	return splitNormalizedSignalValues(signals.EvidenceKV["test_gate"])
}

func validationRequirements(signals findingSignals) []string {
	return splitNormalizedSignalValues(signals.EvidenceKV["validation_requirement"])
}

func splitNormalizedSignalValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(strings.TrimSpace(value), ",") {
			normalized := normalizeToken(part)
			if normalized != "" {
				out = append(out, normalized)
			}
		}
	}
	return dedupeSorted(out)
}

func containsNormalizedValue(values []string, target string) bool {
	target = normalizeToken(target)
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stringSignalState(values []string, missing string) string {
	if len(values) == 0 {
		return missing
	}
	normalized := dedupeSorted(values)
	if len(normalized) == 1 {
		return normalized[0]
	}
	if len(normalized) == 2 {
		onlyMissing := 0
		for _, value := range normalized {
			if value == missing {
				onlyMissing++
			}
		}
		if onlyMissing == 1 {
			for _, value := range normalized {
				if value != missing {
					return value
				}
			}
		}
	}
	return "ambiguous"
}

func boolSignalState(values []string) string {
	if len(values) == 0 {
		return "missing"
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		switch strings.TrimSpace(strings.ToLower(value)) {
		case "true", "1", "yes", "enabled":
			seen["true"] = struct{}{}
		case "false", "0", "no", "disabled":
			seen["false"] = struct{}{}
		default:
			seen["mixed"] = struct{}{}
		}
	}
	if len(seen) == 1 {
		for value := range seen {
			return value
		}
	}
	return "mixed"
}

func hasWriteLikePermission(permissions []string) bool {
	for _, permission := range permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if strings.Contains(normalized, "write") || strings.Contains(normalized, "deploy") || normalized == "merge.execute" {
			return true
		}
	}
	return false
}

func mapFromList(items []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		normalized := normalizeToken(item)
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	return out
}

func extractHost(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	if parsed, err := url.Parse(trimmed); err == nil {
		host := normalizeToken(parsed.Hostname())
		if host != "" {
			return []string{host}
		}
	}
	return nil
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		normalized := normalizeToken(item)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func dedupeSortedPreserveCase(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func normalizeToken(in string) string {
	return strings.ToLower(strings.TrimSpace(in))
}

func fallbackOrg(org string) string {
	trimmed := strings.TrimSpace(org)
	if trimmed == "" {
		return "local"
	}
	return trimmed
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(values))
	out = append(out, values...)
	return out
}

func cloneEvidenceDecision(in *evidencepolicy.Decision) *evidencepolicy.Decision {
	if in == nil {
		return nil
	}
	out := *in
	out.SelectedEvidenceRefs = cloneStringSlice(in.SelectedEvidenceRefs)
	out.ReasonCodes = cloneStringSlice(in.ReasonCodes)
	out.ConflictReasonCodes = cloneStringSlice(in.ConflictReasonCodes)
	if len(in.RejectedCandidates) > 0 {
		out.RejectedCandidates = make([]evidencepolicy.Candidate, 0, len(in.RejectedCandidates))
		for _, item := range in.RejectedCandidates {
			copyItem := item
			copyItem.EvidenceRefs = cloneStringSlice(item.EvidenceRefs)
			copyItem.ReasonCodes = cloneStringSlice(item.ReasonCodes)
			out.RejectedCandidates = append(out.RejectedCandidates, copyItem)
		}
	}
	return &out
}

func cloneLocationRange(value *model.LocationRange) *model.LocationRange {
	if value == nil {
		return nil
	}
	return &model.LocationRange{StartLine: value.StartLine, EndLine: value.EndLine}
}

func locationRangeBounds(value *model.LocationRange) (int, int) {
	if value == nil {
		return 0, 0
	}
	return value.StartLine, value.EndLine
}

func firstRepo(values []string) string {
	if len(values) == 0 {
		return ""
	}
	repos := cloneStringSlice(values)
	sort.Strings(repos)
	return strings.TrimSpace(repos[0])
}

func rangeStart(value *model.LocationRange) int {
	start, _ := locationRangeBounds(value)
	return start
}

func rangeEnd(value *model.LocationRange) int {
	_, end := locationRangeBounds(value)
	return end
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fallbackFramework(framework, toolType string) string {
	trimmed := strings.TrimSpace(framework)
	if trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(toolType)
}
