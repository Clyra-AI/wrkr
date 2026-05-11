package mutableendpoint

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestClassifyReadMethodsDoNotEscalateBusinessMutationSemantics(t *testing.T) {
	t.Parallel()

	semantics := Classify("GET", "/v1/payments", "Get payment", "getPayment", "openapi", "high")
	if !agginventory.HasMutableEndpointSemantic(semantics, agginventory.EndpointSemanticRead) {
		t.Fatalf("expected read semantic for GET payment route, got %+v", semantics)
	}
	for _, forbidden := range []string{
		agginventory.EndpointSemanticPayment,
		agginventory.EndpointSemanticRefund,
		agginventory.EndpointSemanticProductionMutation,
	} {
		if agginventory.HasMutableEndpointSemantic(semantics, forbidden) {
			t.Fatalf("did not expect %s semantic for read-only payment route, got %+v", forbidden, semantics)
		}
	}

	permissions := PermissionsForSemantics(semantics)
	for _, forbidden := range []string{"payment.write", "refund.write", "production.write"} {
		for _, permission := range permissions {
			if permission == forbidden {
				t.Fatalf("did not expect %s for read-only payment route, got %+v", forbidden, permissions)
			}
		}
	}
}

func TestClassifyMethodlessHintsStillCarryMutationSemantics(t *testing.T) {
	t.Parallel()

	semantics := Classify("", "payments-server", "Process customer charges", "payments tools", "mcp", "medium")
	for _, expected := range []string{
		agginventory.EndpointSemanticPayment,
		agginventory.EndpointSemanticProductionMutation,
	} {
		if !agginventory.HasMutableEndpointSemantic(semantics, expected) {
			t.Fatalf("expected %s semantic for methodless MCP hint, got %+v", expected, semantics)
		}
	}
}
