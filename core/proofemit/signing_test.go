package proofemit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestLoadSigningKeyIsAtomicUnderInterruption(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	signingKeyPath := SigningKeyPath(statePath)

	var injected atomic.Bool
	restore := atomicwrite.SetBeforeRenameHookForTest(func(targetPath string, _ string) error {
		if filepath.Clean(targetPath) != filepath.Clean(signingKeyPath) {
			return nil
		}
		if injected.CompareAndSwap(false, true) {
			return errors.New("simulated interruption before rename")
		}
		return nil
	})
	defer restore()

	if _, err := LoadSigningMaterial(statePath); err == nil {
		t.Fatal("expected signing-key initialization interruption failure")
	}
	if _, err := os.Stat(signingKeyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no key file after interrupted initialization, got err=%v", err)
	}

	key, err := LoadSigningMaterial(statePath)
	if err != nil {
		t.Fatalf("load signing material after interruption: %v", err)
	}
	if len(key.Private) == 0 || len(key.Public) == 0 {
		t.Fatalf("expected valid signing key after retry, got %+v", key)
	}
}

func TestLoadSigningKeyConcurrentInitializationProducesSingleValidState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	const workers = 8
	type result struct {
		keyID   string
		public  []byte
		private []byte
		err     error
	}

	results := make(chan result, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			key, err := LoadSigningMaterial(statePath)
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{
				keyID:   key.KeyID,
				public:  append([]byte(nil), key.Public...),
				private: append([]byte(nil), key.Private...),
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var first result
	for item := range results {
		if item.err != nil {
			t.Fatalf("concurrent signing-material load failed: %v", item.err)
		}
		if len(first.private) == 0 {
			first = item
			continue
		}
		if item.keyID != first.keyID {
			t.Fatalf("expected stable key id across concurrent initialization, got %q and %q", first.keyID, item.keyID)
		}
		if !bytes.Equal(item.public, first.public) {
			t.Fatalf("expected stable public key across concurrent initialization")
		}
		if !bytes.Equal(item.private, first.private) {
			t.Fatalf("expected stable private key across concurrent initialization")
		}
	}

	stored, err := LoadSigningMaterial(statePath)
	if err != nil {
		t.Fatalf("load persisted signing material: %v", err)
	}
	if stored.KeyID != first.keyID {
		t.Fatalf("expected persisted key id %q, got %q", first.keyID, stored.KeyID)
	}
	if !bytes.Equal(stored.Public, first.public) {
		t.Fatalf("expected persisted public key to match concurrent result")
	}
	if !bytes.Equal(stored.Private, first.private) {
		t.Fatalf("expected persisted private key to match concurrent result")
	}
}
