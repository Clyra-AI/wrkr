package statelock

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireBlocksOtherProcessLeaseUntilRelease(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "state.json")
	first, err := Acquire(context.Background(), statePath)
	if err != nil {
		t.Fatalf("Acquire(first) error = %v", err)
	}
	defer func() { _ = first.Release() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, statePath); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire(second) error = %v, want context deadline", err)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	first = nil
	third, err := Acquire(context.Background(), statePath)
	if err != nil {
		t.Fatalf("Acquire(after release) error = %v", err)
	}
	if err := third.Release(); err != nil {
		t.Fatalf("Release(third) error = %v", err)
	}
}
