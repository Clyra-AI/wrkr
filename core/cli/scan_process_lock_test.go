package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/proofemit"
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
)

const (
	scanProcessHelperEnv = "WRKR_SCAN_PROCESS_HELPER"
	scanProcessRootEnv   = "WRKR_SCAN_PROCESS_ROOT"
	scanProcessStateEnv  = "WRKR_SCAN_PROCESS_STATE"
)

func TestScanProcessHelper(t *testing.T) {
	if os.Getenv(scanProcessHelperEnv) != "1" {
		return
	}
	os.Exit(Run([]string{
		"scan",
		"--path", os.Getenv(scanProcessRootEnv),
		"--state", os.Getenv(scanProcessStateEnv),
		"--quiet",
	}, os.Stdout, os.Stderr))
}

func TestConcurrentScanProcessesPreserveCompleteProofChain(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", "scenarios", "wrkr", "scan-mixed-org", "repos"))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}

	sequentialState := filepath.Join(t.TempDir(), "sequential", "state.json")
	runScanProcess(t, repoRoot, sequentialState)
	runScanProcess(t, repoRoot, sequentialState)
	sequentialCount := proofChainRecordCount(t, sequentialState)

	concurrentState := filepath.Join(t.TempDir(), "concurrent", "state.json")
	first := scanProcessCommand(t, repoRoot, concurrentState)
	second := scanProcessCommand(t, repoRoot, concurrentState)
	if err := first.Start(); err != nil {
		t.Fatalf("start first scan: %v", err)
	}
	if err := second.Start(); err != nil {
		t.Fatalf("start second scan: %v", err)
	}
	if err := first.Wait(); err != nil {
		t.Fatalf("first scan failed: %v\nstderr=%s", err, first.Stderr.(*bytes.Buffer).String())
	}
	if err := second.Wait(); err != nil {
		t.Fatalf("second scan failed: %v\nstderr=%s", err, second.Stderr.(*bytes.Buffer).String())
	}
	concurrentCount := proofChainRecordCount(t, concurrentState)
	if concurrentCount != sequentialCount {
		t.Fatalf("concurrent proof records = %d, sequential proof records = %d", concurrentCount, sequentialCount)
	}
}

func runScanProcess(t *testing.T, repoRoot, statePath string) {
	t.Helper()
	command := scanProcessCommand(t, repoRoot, statePath)
	if err := command.Run(); err != nil {
		t.Fatalf("scan process failed: %v\nstderr=%s", err, command.Stderr.(*bytes.Buffer).String())
	}
}

func scanProcessCommand(t *testing.T, repoRoot, statePath string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestScanProcessHelper$") // #nosec G204 -- runs the current test binary with fixed arguments.
	command.Env = append(os.Environ(),
		scanProcessHelperEnv+"=1",
		scanProcessRootEnv+"="+repoRoot,
		scanProcessStateEnv+"="+statePath,
	)
	command.Stdout = &bytes.Buffer{}
	command.Stderr = &bytes.Buffer{}
	return command
}

func proofChainRecordCount(t *testing.T, statePath string) int {
	t.Helper()
	chainPath := proofemit.ChainPath(statePath)
	chain, err := proofemit.LoadChain(chainPath)
	if err != nil {
		t.Fatalf("load proof chain: %v", err)
	}
	result, err := verifycore.Chain(chainPath)
	if err != nil {
		t.Fatalf("verify proof chain: %v", err)
	}
	if !result.Intact {
		t.Fatalf("proof chain is not intact: %+v", result)
	}
	return len(chain.Records)
}
