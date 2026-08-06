// Package statelock serializes operations that read or update a managed state directory.
package statelock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const (
	fileName       = ".wrkr-managed.lock"
	defaultTimeout = 10 * time.Minute
	retryDelay     = 25 * time.Millisecond
)

var ErrBusy = errors.New("managed artifact state is busy")

// Lease is an exclusive, cross-process lock for a managed artifact directory.
type Lease struct {
	lock     *flock.Flock
	lockPath string
}

type ownerMetadata struct {
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
}

func Acquire(ctx context.Context, statePath string) (*Lease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dir := filepath.Dir(filepath.Clean(strings.TrimSpace(statePath)))
	if dir == "" || dir == "." {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create managed artifact lock directory: %w", err)
	}

	lockCtx := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		lockCtx, cancel = context.WithTimeout(ctx, defaultTimeout)
	}
	defer cancel()

	lockPath := filepath.Join(dir, fileName)
	lock := flock.New(lockPath)
	locked, err := lock.TryLockContext(lockCtx, retryDelay)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("acquire managed artifact lock: %w", ctx.Err())
			}
			return nil, busyError(statePath, lockPath)
		}
		return nil, fmt.Errorf("acquire managed artifact lock: %w", err)
	}
	if !locked {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("acquire managed artifact lock: %w", ctx.Err())
		}
		return nil, busyError(statePath, lockPath)
	}
	lease := &Lease{lock: lock, lockPath: lockPath}
	if err := lease.writeOwnerMetadata(); err != nil {
		_ = lease.Release()
		return nil, err
	}
	return lease, nil
}

func (l *Lease) Release() error {
	if l == nil || l.lock == nil {
		return nil
	}
	err := l.lock.Unlock()
	l.lock = nil
	if err != nil {
		return fmt.Errorf("release managed artifact lock: %w", err)
	}
	return nil
}

func (l *Lease) writeOwnerMetadata() error {
	if l == nil || strings.TrimSpace(l.lockPath) == "" {
		return nil
	}
	file, err := os.OpenFile(l.lockPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("write managed artifact lock metadata: %w", err)
	}
	defer file.Close()
	metadata := ownerMetadata{
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := json.NewEncoder(file).Encode(metadata); err != nil {
		return fmt.Errorf("write managed artifact lock metadata: %w", err)
	}
	return nil
}

func busyError(statePath, lockPath string) error {
	stateLabel := filepath.Clean(strings.TrimSpace(statePath))
	message := fmt.Sprintf("state %s is locked by another wrkr scan; wait for it to finish or use a separate --state path", stateLabel)
	if metadata, err := readOwnerMetadata(lockPath); err == nil && metadata.PID > 0 {
		message += fmt.Sprintf(" (lock metadata pid=%d started_at=%s)", metadata.PID, metadata.StartedAt)
	}
	return fmt.Errorf("%w: %s", ErrBusy, message)
}

func readOwnerMetadata(lockPath string) (ownerMetadata, error) {
	payload, err := os.ReadFile(lockPath)
	if err != nil {
		return ownerMetadata{}, err
	}
	var metadata ownerMetadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return ownerMetadata{}, err
	}
	return metadata, nil
}
