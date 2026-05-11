package mutableendpoint

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
)

func Classify(method, route, summary, name, surface, confidence string) []agginventory.MutableEndpointSemantic {
	method = strings.ToUpper(strings.TrimSpace(method))
	route = strings.TrimSpace(route)
	summary = strings.TrimSpace(summary)
	name = strings.TrimSpace(name)
	surface = strings.TrimSpace(surface)
	confidence = strings.TrimSpace(confidence)
	if confidence == "" {
		confidence = "low"
	}

	operation := strings.TrimSpace(strings.Join(strings.Fields(strings.TrimSpace(method+" "+route)), " "))
	if operation == "" {
		operation = strings.TrimSpace(name)
	}
	text := strings.ToLower(strings.Join([]string{operation, summary, name}, " "))
	readOnlyMethod := method == "GET" || method == "HEAD" || method == "OPTIONS"

	semantics := []agginventory.MutableEndpointSemantic{}
	add := func(semantic string) {
		if strings.TrimSpace(semantic) == "" {
			return
		}
		semantics = append(semantics, agginventory.MutableEndpointSemantic{
			Semantic:     semantic,
			Confidence:   confidence,
			Surface:      surface,
			Operation:    operation,
			EvidenceRefs: compactEvidenceRefs(operation, summary, name),
		})
	}

	switch method {
	case "GET", "HEAD", "OPTIONS":
		add(agginventory.EndpointSemanticRead)
	case "DELETE":
		add(agginventory.EndpointSemanticDelete)
	case "POST", "PUT", "PATCH":
		add(agginventory.EndpointSemanticWrite)
	}

	switch {
	case strings.Contains(text, "refund"):
		if !readOnlyMethod {
			add(agginventory.EndpointSemanticRefund)
			add(agginventory.EndpointSemanticProductionMutation)
		}
	case strings.Contains(text, "payment"), strings.Contains(text, "charge"), strings.Contains(text, "invoice"):
		if !readOnlyMethod {
			add(agginventory.EndpointSemanticPayment)
			add(agginventory.EndpointSemanticProductionMutation)
		}
	}
	switch {
	case strings.Contains(text, "admin"), strings.Contains(text, "role"), strings.Contains(text, "member"), strings.Contains(text, "invite"), strings.Contains(text, "user"):
		if !readOnlyMethod && (strings.Contains(text, "/user") || strings.Contains(text, "user_") || strings.Contains(text, "user ") || strings.Contains(text, "admin") || strings.Contains(text, "role") || strings.Contains(text, "member") || strings.Contains(text, "invite")) {
			add(agginventory.EndpointSemanticUserAdmin)
		}
	case strings.Contains(text, "rbac"):
		if !readOnlyMethod {
			add(agginventory.EndpointSemanticUserAdmin)
		}
	}
	if strings.Contains(text, "export") || strings.Contains(text, "download") || strings.Contains(text, "csv") || strings.Contains(text, "dump") {
		add(agginventory.EndpointSemanticDataExport)
	}
	if !readOnlyMethod && (strings.Contains(text, "deploy") || strings.Contains(text, "release") || strings.Contains(text, "publish") || strings.Contains(text, "rollout") || strings.Contains(text, "migrate")) {
		add(agginventory.EndpointSemanticDeploy)
		add(agginventory.EndpointSemanticProductionMutation)
	}
	if !readOnlyMethod && (method == "DELETE" || method == "PATCH" || method == "PUT" || strings.Contains(text, "prod") || strings.Contains(text, "live") || strings.Contains(text, "customer")) {
		add(agginventory.EndpointSemanticProductionMutation)
	}

	return agginventory.NormalizeMutableEndpointSemantics(semantics)
}

func PermissionsForSemantics(values []agginventory.MutableEndpointSemantic) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, item := range values {
		switch strings.TrimSpace(item.Semantic) {
		case agginventory.EndpointSemanticRead:
			set["api.read"] = struct{}{}
		case agginventory.EndpointSemanticWrite:
			set["api.write"] = struct{}{}
		case agginventory.EndpointSemanticDelete:
			set["api.delete"] = struct{}{}
			set["production.write"] = struct{}{}
		case agginventory.EndpointSemanticDeploy:
			set["deploy.write"] = struct{}{}
		case agginventory.EndpointSemanticRefund:
			set["refund.write"] = struct{}{}
		case agginventory.EndpointSemanticPayment:
			set["payment.write"] = struct{}{}
		case agginventory.EndpointSemanticUserAdmin:
			set["user_admin.write"] = struct{}{}
		case agginventory.EndpointSemanticDataExport:
			set["data_export.write"] = struct{}{}
		case agginventory.EndpointSemanticProductionMutation:
			set["production.write"] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for permission := range set {
		out = append(out, permission)
	}
	sort.Strings(out)
	return out
}

func EncodeEvidenceValues(values []agginventory.MutableEndpointSemantic) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, item := range agginventory.NormalizeMutableEndpointSemantics(values) {
		out = append(out, strings.Join([]string{
			strings.TrimSpace(item.Semantic),
			strings.TrimSpace(item.Confidence),
			strings.TrimSpace(item.Surface),
			strings.TrimSpace(item.Operation),
		}, "|"))
	}
	return out
}

func SeverityForSemantics(values []agginventory.MutableEndpointSemantic) string {
	if agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticPayment) ||
		agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticRefund) ||
		agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticUserAdmin) ||
		agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticDelete) ||
		agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticProductionMutation) ||
		agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticDeploy) {
		return model.SeverityHigh
	}
	if agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticWrite) ||
		agginventory.HasMutableEndpointSemantic(values, agginventory.EndpointSemanticDataExport) {
		return model.SeverityMedium
	}
	return model.SeverityLow
}

func compactEvidenceRefs(values ...string) []string {
	out := []string{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
