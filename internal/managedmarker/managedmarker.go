package managedmarker

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
	"os"
)

const version = "v2"
const tokenFileName = ".wrkr-managed-token" // #nosec G101 -- filename constant for local token storage, not credential material.

type payload struct {
	Version    string `json:"version"`
	Kind       string `json:"kind"`
	TargetPath string `json:"target_path"`
	MAC        string `json:"hmac_sha256"`
}

func BuildPayload(statePath, targetPath, kind string) ([]byte, error) {
	token, err := loadOrCreateToken(statePath)
	if err != nil {
		return nil, err
	}
	canonicalTarget, err := canonicalTargetPath(targetPath)
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(payload{
		Version:    version,
		Kind:       strings.TrimSpace(kind),
		TargetPath: canonicalTarget,
		MAC:        sign(token, strings.TrimSpace(kind), canonicalTarget),
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal managed marker: %w", err)
	}
	return append(encoded, '\n'), nil
}

func ValidatePayload(statePath, targetPath, kind string, raw []byte) error {
	canonicalTarget, err := canonicalTargetPath(targetPath)
	if err != nil {
		return err
	}
	var parsed payload
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("parse managed marker: %w", err)
	}
	if strings.TrimSpace(parsed.Version) != version {
		return fmt.Errorf("managed marker version mismatch: have %q want %q", parsed.Version, version)
	}
	if strings.TrimSpace(parsed.Kind) != strings.TrimSpace(kind) {
		return fmt.Errorf("managed marker kind mismatch: have %q want %q", parsed.Kind, kind)
	}
	if strings.TrimSpace(parsed.TargetPath) != canonicalTarget {
		return fmt.Errorf("managed marker target mismatch: have %q want %q", parsed.TargetPath, canonicalTarget)
	}
	token, err := loadToken(statePath)
	if err != nil {
		return err
	}
	expected := sign(token, strings.TrimSpace(kind), canonicalTarget)
	if !hmac.Equal([]byte(strings.TrimSpace(parsed.MAC)), []byte(expected)) {
		return fmt.Errorf("managed marker signature is invalid")
	}
	return nil
}

func canonicalTargetPath(targetPath string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(targetPath))
	if clean == "" || clean == "." {
		return "", fmt.Errorf("managed marker target path is required")
	}
	absolute, err := filepath.Abs(clean)
	if err != nil {
		return "", fmt.Errorf("resolve managed marker target path: %w", err)
	}
	return filepath.Clean(absolute), nil
}

func loadOrCreateToken(statePath string) ([]byte, error) {
	if token, err := loadToken(statePath); err == nil {
		return token, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	encoded := make([]byte, 64)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("generate managed marker token: %w", err)
	}
	hex.Encode(encoded, random)
	encoded = append(encoded, '\n')
	if err := atomicwrite.WriteFile(tokenPath(statePath), encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write managed marker token: %w", err)
	}
	return random, nil
}

func loadToken(statePath string) ([]byte, error) {
	raw, err := os.ReadFile(tokenPath(statePath)) // #nosec G304 -- token path is derived from explicit state-path configuration.
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("parse managed marker token: %w", err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("managed marker token is empty")
	}
	return decoded, nil
}

func tokenPath(statePath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(strings.TrimSpace(statePath))), tokenFileName)
}

func sign(token []byte, kind, targetPath string) string {
	mac := hmac.New(sha256.New, token)
	_, _ = mac.Write([]byte(strings.TrimSpace(kind)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strings.TrimSpace(targetPath)))
	return hex.EncodeToString(mac.Sum(nil))
}
