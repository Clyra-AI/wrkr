package auth

import "testing"

func TestResolveFixTokenPrecedence(t *testing.T) {
	t.Parallel()

	token, err := ResolveFixToken("scan-token", "fix-token", "override")
	if err != nil {
		t.Fatalf("resolve token: %v", err)
	}
	if token != "override" {
		t.Fatalf("expected override token, got %q", token)
	}

	token, err = ResolveFixToken("scan-token", "fix-token", "")
	if err != nil {
		t.Fatalf("resolve fix token: %v", err)
	}
	if token != "fix-token" {
		t.Fatalf("expected fix token, got %q", token)
	}
}

func TestResolveFixTokenFailsClosedWithScanOnly(t *testing.T) {
	t.Parallel()

	_, err := ResolveFixToken("scan-token", "", "")
	if err == nil {
		t.Fatal("expected scan-only profile to fail closed")
	}
	if err != ErrFixProfileRequired {
		t.Fatalf("expected ErrFixProfileRequired, got %v", err)
	}
}
