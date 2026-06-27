package report

import (
	"strings"
	"testing"
)

func TestBuyerArtifactQABlocksWeakBlockedCredentialLead(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		Texts: map[string]string{
			"markdown": "# Wrkr Deterministic Report\n\n## What To Look At First\n\n- Inspect first: workflow in repo via loc. Why: blocked path with standing credential. Evidence found: control visible. Evidence unresolved: approval. Recommended action: Accept risk with expiry | Attach policy or proof reference | Reduce standing credential scope.\n\n## Report Context Appendix\n\n- detail=ok\n",
		},
	})
	if err == nil {
		t.Fatal("expected weak blocked-credential lead to fail QA")
	}
	if !strings.Contains(err.Error(), "accept-risk") {
		t.Fatalf("expected accept-risk QA issue, got %v", err)
	}
}

func TestBuyerArtifactQAAllowsStrongBlockedCredentialLead(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		Texts: map[string]string{
			"markdown": "# Wrkr Deterministic Report\n\n## What To Look At First\n\n- Inspect first: workflow in repo via loc. Why: blocked path with standing credential. Evidence found: control visible. Evidence unresolved: approval. Recommended action: Replace standing credential with brokered JIT access | Accept risk with expiry.\n\n## Report Context Appendix\n\n- recommended_control=block_standing_credential\n",
		},
	})
	if err != nil {
		t.Fatalf("expected strong blocked-credential lead to pass even with appendix tokens, got %v", err)
	}
}

func TestBuyerArtifactQAScopesBlockedCredentialOrderingPerLeadCard(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		Texts: map[string]string{
			"markdown": "# Wrkr Deterministic Report\n\n## What To Look At First\n\n1. Inspect: workflow in repo via loc-a.\n  Why: approval-required path.\n  Evidence: control visible; unresolved: proof.\n  Action: Accept risk with expiry.\n2. Inspect: workflow in repo via loc-b.\n  Why: blocked path with standing credential.\n  Evidence: control visible; unresolved: approval.\n  Action: Replace standing credential with brokered JIT access.\n\n## Report Context Appendix\n\n- detail=ok\n",
		},
	})
	if err != nil {
		t.Fatalf("expected accept-risk in a separate non-blocked card to pass QA, got %v", err)
	}
}

func TestBuyerArtifactQALeadCardParsingStopsAtNextSection(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		Texts: map[string]string{
			"markdown": "# Wrkr Deterministic Report\n\n## What To Look At First\n\n1. Inspect: workflow in repo via loc-a.\n  Why: approval-required path.\n  Evidence: control visible; unresolved: proof.\n  Action: Accept risk with expiry.\n\n## Top Action Paths\n\n- blocked standing credential path should not be folded into the previous lead card.\n\n## Report Context Appendix\n\n- detail=ok\n",
		},
	})
	if err != nil {
		t.Fatalf("expected later sections not to be folded into the last lead card, got %v", err)
	}
}

func TestBuyerArtifactQABlocksPrimaryInternalTokensAndRepeatedEvidenceGaps(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		Texts: map[string]string{
			"markdown": "# Wrkr Deterministic Report\n\n## What To Look At First\n\n- Inspect first: workflow in repo via loc. Why: production_impacting path. Evidence found: approval=approval evidence not found proof=path-specific proof not found. Evidence unresolved: approval. Recommended action: review.\n- Inspect next: workflow in repo via loc-2. Why: production path. Evidence found: approval=approval evidence not found proof=path-specific proof not found. Evidence unresolved: proof. Recommended action: review.\n\n## Report Context Appendix\n\n- detail=ok\n",
		},
	})
	if err == nil {
		t.Fatal("expected internal tokens and repeated raw evidence gaps to fail QA")
	}
	for _, want := range []string{"production_impacting", "repeats raw approval", "repeats raw proof"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected QA issue %q, got %v", want, err)
		}
	}
}

func TestBuyerArtifactQABlocksOverlongPrimaryLine(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		Texts: map[string]string{
			"markdown": "# Wrkr Deterministic Report\n\n## What To Look At First\n\n- Inspect first: " + strings.Repeat("dense field dump ", 50) + "\n\n## Report Context Appendix\n\n- detail=ok\n",
		},
	})
	if err == nil {
		t.Fatal("expected overlong primary line to fail QA")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected line-length QA issue, got %v", err)
	}
}
