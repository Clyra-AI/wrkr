// Package statelock serializes operations that read or update a managed state directory.
package statelock

import (
	"context"
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
	lock *flock.Flock
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

	lock := flock.New(filepath.Join(dir, fileName))
	locked, err := lock.TryLockContext(lockCtx, retryDelay)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("acquire managed artifact lock: %w", ctx.Err())
			}
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("acquire managed artifact lock: %w", err)
	}
	if !locked {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("acquire managed artifact lock: %w", ctx.Err())
		}
		return nil, ErrBusy
	}
	return &Lease{lock: lock}, nil
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
