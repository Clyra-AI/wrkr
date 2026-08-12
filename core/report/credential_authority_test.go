package report

import agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"

func testStandingCredentialAuthority(kind string) *agginventory.CredentialAuthority {
	return &agginventory.CredentialAuthority{
		EvidenceStage:          agginventory.EvidenceStageEffectiveAuthority,
		ExistenceEvidenceState: agginventory.AuthorityEvidenceVerified,
		BindingEvidenceState:   agginventory.AuthorityEvidenceVerified,
		LifetimeEvidenceState:  agginventory.AuthorityEvidenceVerified,
		LifetimeKind:           agginventory.CredentialLifetimeStanding,
		CredentialKind:         kind,
		AccessType:             agginventory.CredentialAccessTypeStanding,
	}
}
