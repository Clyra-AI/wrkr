package proofemit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	proof "github.com/Clyra-AI/proof"
)

const envProofPrivateKey = "WRKR_PROOF_PRIVATE_KEY_B64"
const envProofPublicKey = "WRKR_PROOF_PUBLIC_KEY_B64"
const envProofKeyID = "WRKR_PROOF_KEY_ID"

type keyFile struct {
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func keyPath(statePath string) string {
	dir := filepath.Dir(strings.TrimSpace(statePath))
	if dir == "" || dir == "." {
		dir = ".wrkr"
	}
	return filepath.Join(dir, "proof-signing-key.json")
}

func HasEnvSigningKey() bool {
	return strings.TrimSpace(os.Getenv(envProofPrivateKey)) != ""
}

func loadSigningKey(statePath string) (proof.SigningKey, error) {
	path := keyPath(statePath)
	if value := strings.TrimSpace(os.Getenv(envProofPrivateKey)); value != "" {
		privateKey, err := decodePrivateKey(value)
		if err != nil {
			return proof.SigningKey{}, fmt.Errorf("decode %s: %w", envProofPrivateKey, err)
		}
		publicKey := privateKey.Public().(ed25519.PublicKey)
		keyID := strings.TrimSpace(os.Getenv(envProofKeyID))
		return proof.SigningKey{Private: privateKey, Public: publicKey, KeyID: keyID}, nil
	}

	payload, err := os.ReadFile(path) // #nosec G304 -- path is a deterministic local wrkr key location under state directory.
	if err == nil {
		var stored keyFile
		if err := json.Unmarshal(payload, &stored); err != nil {
			return proof.SigningKey{}, fmt.Errorf("parse key file: %w", err)
		}
		privateKey, err := decodePrivateKey(stored.PrivateKey)
		if err != nil {
			return proof.SigningKey{}, fmt.Errorf("decode private key: %w", err)
		}
		publicKey, err := decodePublicKey(stored.PublicKey)
		if err != nil {
			return proof.SigningKey{}, fmt.Errorf("decode public key: %w", err)
		}
		if !publicKey.Equal(privateKey.Public().(ed25519.PublicKey)) {
			return proof.SigningKey{}, fmt.Errorf("key file public key does not match private key")
		}
		return proof.SigningKey{Private: privateKey, Public: publicKey, KeyID: strings.TrimSpace(stored.KeyID)}, nil
	}
	if !os.IsNotExist(err) {
		return proof.SigningKey{}, fmt.Errorf("read key file: %w", err)
	}

	generated, err := proof.GenerateSigningKey()
	if err != nil {
		return proof.SigningKey{}, fmt.Errorf("generate signing key: %w", err)
	}
	stored := keyFile{
		KeyID:      generated.KeyID,
		PublicKey:  base64.StdEncoding.EncodeToString(generated.Public),
		PrivateKey: base64.StdEncoding.EncodeToString(generated.Private),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return proof.SigningKey{}, fmt.Errorf("mkdir key dir: %w", err)
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return proof.SigningKey{}, fmt.Errorf("marshal key file: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return proof.SigningKey{}, fmt.Errorf("write key file: %w", err)
	}
	return generated, nil
}

func loadPublicKey(statePath string) (proof.PublicKey, error) {
	if value := strings.TrimSpace(os.Getenv(envProofPublicKey)); value != "" {
		publicKey, err := decodePublicKey(value)
		if err != nil {
			return proof.PublicKey{}, fmt.Errorf("decode %s: %w", envProofPublicKey, err)
		}
		keyID := strings.TrimSpace(os.Getenv(envProofKeyID))
		return proof.PublicKey{Public: publicKey, KeyID: keyID}, nil
	}

	path := keyPath(statePath)
	payload, err := os.ReadFile(path) // #nosec G304 -- path is a deterministic local wrkr key location under state directory.
	if err != nil {
		return proof.PublicKey{}, fmt.Errorf("read key file: %w", err)
	}
	var stored keyFile
	if err := json.Unmarshal(payload, &stored); err != nil {
		return proof.PublicKey{}, fmt.Errorf("parse key file: %w", err)
	}
	publicKey, err := decodePublicKey(stored.PublicKey)
	if err != nil {
		return proof.PublicKey{}, fmt.Errorf("decode public key: %w", err)
	}
	return proof.PublicKey{Public: publicKey, KeyID: strings.TrimSpace(stored.KeyID)}, nil
}

func decodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length %d", len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
