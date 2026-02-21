package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runIdentity(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "identity subcommand is required", exitInvalidInput)
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stderr, "Usage of wrkr identity: identity <list|show|approve|review|deprecate|revoke> [flags]")
		return exitSuccess
	}
	subcommand := args[0]
	subArgs := args[1:]
	switch subcommand {
	case "list":
		return runIdentityList(subArgs, stdout, stderr)
	case "show":
		return runIdentityShow(subArgs, stdout, stderr)
	case "approve":
		return runIdentityApprove(subArgs, stdout, stderr)
	case "review":
		return runIdentityTransition(subArgs, stdout, stderr, identity.StateUnderReview)
	case "deprecate":
		return runIdentityTransition(subArgs, stdout, stderr, identity.StateDeprecated)
	case "revoke":
		return runIdentityTransition(subArgs, stdout, stderr, identity.StateRevoked)
	default:
		return emitError(stderr, wantsJSONOutput(subArgs), "invalid_input", "unsupported identity subcommand", exitInvalidInput)
	}
}

func runIdentityList(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("identity list", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	loaded, err := manifest.Load(manifest.ResolvePath(state.ResolvePath(*statePathFlag)))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	identities := append([]manifest.IdentityRecord(nil), loaded.Identities...)
	sort.Slice(identities, func(i, j int) bool { return identities[i].AgentID < identities[j].AgentID })
	payload := map[string]any{"status": "ok", "identities": identities}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr identity count=%d\n", len(identities))
	return exitSuccess
}

func runIdentityShow(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	preID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		preID = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("identity show", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	agentID := strings.TrimSpace(preID)
	if agentID == "" {
		if fs.NArg() != 1 {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "identity id is required", exitInvalidInput)
		}
		agentID = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "identity id is required", exitInvalidInput)
	}
	statePath := state.ResolvePath(*statePathFlag)
	loaded, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	var record *manifest.IdentityRecord
	for i := range loaded.Identities {
		if loaded.Identities[i].AgentID == agentID {
			copyRecord := loaded.Identities[i]
			record = &copyRecord
			break
		}
	}
	if record == nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "identity not found", exitInvalidInput)
	}
	chain, chainErr := lifecycle.LoadChain(lifecycle.ChainPath(statePath))
	if chainErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", chainErr.Error(), exitRuntime)
	}
	payload := map[string]any{
		"status":   "ok",
		"identity": record,
		"history":  lifecycle.RecordsForAgent(chain, agentID),
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr identity %s status=%s\n", record.AgentID, record.Status)
	return exitSuccess
}

func runIdentityApprove(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	preID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		preID = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("identity approve", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	approver := fs.String("approver", "", "approver identity")
	scope := fs.String("scope", "", "approval scope")
	expires := fs.String("expires", "90d", "approval validity duration")
	statePathFlag := fs.String("state", "", "state file path override")
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	agentID := strings.TrimSpace(preID)
	if agentID == "" {
		if fs.NArg() != 1 {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "identity id is required", exitInvalidInput)
		}
		agentID = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "identity id is required", exitInvalidInput)
	}
	if strings.TrimSpace(*approver) == "" || strings.TrimSpace(*scope) == "" {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--approver and --scope are required", exitInvalidInput)
	}
	expiresAt, expiryErr := lifecycle.ParseExpiry(*expires, time.Now().UTC().Truncate(time.Second))
	if expiryErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", expiryErr.Error(), exitInvalidInput)
	}
	transitionCode := runIdentityManualTransition(identity.StateApproved, agentID, strings.TrimSpace(*approver), strings.TrimSpace(*scope), "", expiresAt, *statePathFlag, jsonRequested || *jsonOut, stdout, stderr)
	return transitionCode
}

func runIdentityTransition(args []string, stdout io.Writer, stderr io.Writer, stateName string) int {
	jsonRequested := wantsJSONOutput(args)
	preID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		preID = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("identity transition", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	reason := fs.String("reason", "", "transition reason")
	statePathFlag := fs.String("state", "", "state file path override")
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	agentID := strings.TrimSpace(preID)
	if agentID == "" {
		if fs.NArg() != 1 {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "identity id is required", exitInvalidInput)
		}
		agentID = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "identity id is required", exitInvalidInput)
	}
	return runIdentityManualTransition(stateName, agentID, "", "", strings.TrimSpace(*reason), time.Time{}, *statePathFlag, jsonRequested || *jsonOut, stdout, stderr)
}

func runIdentityManualTransition(stateName, agentID, approver, scope, reason string, expiresAt time.Time, statePathFlag string, jsonOut bool, stdout io.Writer, stderr io.Writer) int {
	statePath := state.ResolvePath(statePathFlag)
	manifestPath := manifest.ResolvePath(statePath)
	loaded, err := manifest.Load(manifestPath)
	if err != nil {
		return emitError(stderr, jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	now := time.Now().UTC().Truncate(time.Second)
	nextManifest, transition, transitionErr := lifecycle.ApplyManualState(loaded, agentID, stateName, approver, scope, reason, expiresAt, now)
	if transitionErr != nil {
		return emitError(stderr, jsonOut, "invalid_input", transitionErr.Error(), exitInvalidInput)
	}
	if err := manifest.Save(manifestPath, nextManifest); err != nil {
		return emitError(stderr, jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	chainPath := lifecycle.ChainPath(statePath)
	chain, chainErr := lifecycle.LoadChain(chainPath)
	if chainErr != nil {
		return emitError(stderr, jsonOut, "runtime_failure", chainErr.Error(), exitRuntime)
	}
	eventType := "lifecycle_transition"
	if stateName == identity.StateApproved || stateName == identity.StateActive {
		eventType = "approval"
	}
	if err := lifecycle.AppendTransitionRecord(chain, transition, eventType); err != nil {
		return emitError(stderr, jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	if err := lifecycle.SaveChain(chainPath, chain); err != nil {
		return emitError(stderr, jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	if err := proofemit.EmitIdentityTransition(statePath, transition, eventType); err != nil {
		return emitError(stderr, jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	payload := map[string]any{"status": "ok", "transition": transition}
	if jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr identity %s -> %s\n", agentID, stateName)
	return exitSuccess
}
