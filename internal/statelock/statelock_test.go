package statelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	metadataPath := first.metadataPath
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
	if _, err := os.Stat(metadataPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner metadata remains after Release: %v", err)
	}
	third, err := Acquire(context.Background(), statePath)
	if err != nil {
		t.Fatalf("Acquire(after release) error = %v", err)
	}
	if err := third.Release(); err != nil {
		t.Fatalf("Release(third) error = %v", err)
	}
}

func TestBusyErrorIncludesStateAndOwnerMetadata(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	lease, err := Acquire(context.Background(), statePath)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = lease.Release() }()

	metadata, err := readOwnerMetadata(lease.metadataPath)
	if err != nil {
		t.Fatalf("readOwnerMetadata() error = %v", err)
	}
	if metadata.PID <= 0 || metadata.StartedAt == "" {
		t.Fatalf("unexpected owner metadata: %+v", metadata)
	}

	busy := busyError(statePath, lease.metadataPath)
	if !errors.Is(busy, ErrBusy) {
		t.Fatalf("busyError() = %v, want ErrBusy", busy)
	}
	for _, want := range []string{filepath.Clean(statePath), "pid=", "separate --state path"} {
		if !strings.Contains(busy.Error(), want) {
			t.Fatalf("busyError() missing %q: %v", want, busy)
		}
	}
}

func TestLeaseMetadataHelpersHandleAbsentOrMalformedMetadata(t *testing.T) {
	var nilLease *Lease
	if err := nilLease.writeOwnerMetadata(); err != nil {
		t.Fatalf("nil writeOwnerMetadata() error = %v", err)
	}
	if err := nilLease.removeOwnerMetadata(); err != nil {
		t.Fatalf("nil removeOwnerMetadata() error = %v", err)
	}
	if err := (&Lease{}).writeOwnerMetadata(); err != nil {
		t.Fatalf("empty writeOwnerMetadata() error = %v", err)
	}
	if err := (&Lease{}).removeOwnerMetadata(); err != nil {
		t.Fatalf("empty removeOwnerMetadata() error = %v", err)
	}

	metadataPath := filepath.Join(t.TempDir(), "owner.json")
	if _, err := readOwnerMetadata(metadataPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readOwnerMetadata(missing) error = %v, want not exist", err)
	}
	if err := os.WriteFile(metadataPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write malformed owner metadata: %v", err)
	}
	if _, err := readOwnerMetadata(metadataPath); err == nil {
		t.Fatal("readOwnerMetadata(malformed) error = nil, want error")
	}
}

func TestOwnerMetadataRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	victimPath := filepath.Join(root, "victim.json")
	if err := os.WriteFile(victimPath, []byte("preserve this payload"), 0o600); err != nil {
		t.Fatalf("write victim metadata: %v", err)
	}
	metadataPath := filepath.Join(root, metadataName)
	if err := os.Symlink(victimPath, metadataPath); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	lease := &Lease{metadataPath: metadataPath}
	if err := lease.writeOwnerMetadata(); err == nil {
		t.Fatal("writeOwnerMetadata() error = nil, want symlink rejection")
	}
	if _, err := readOwnerMetadata(metadataPath); err == nil {
		t.Fatal("readOwnerMetadata() error = nil, want symlink rejection")
	}
	payload, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("read victim metadata: %v", err)
	}
	if want := "preserve this payload"; string(payload) != want {
		t.Fatalf("victim metadata = %q, want %q", payload, want)
	}
}

func TestOwnerMetadataFileRejectsNegativeDescriptor(t *testing.T) {
	file, err := ownerMetadataFileFromDescriptor(-1, "owner.json")
	if err == nil {
		if file != nil {
			_ = file.Close()
		}
		t.Fatal("ownerMetadataFileFromDescriptor() error = nil, want invalid descriptor rejection")
	}
	if file != nil {
		t.Fatalf("ownerMetadataFileFromDescriptor() file = %v, want nil", file)
	}
	if !strings.Contains(err.Error(), "invalid descriptor") {
		t.Fatalf("ownerMetadataFileFromDescriptor() error = %v, want invalid descriptor", err)
	}
}
