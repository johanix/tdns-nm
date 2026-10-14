/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC JOSE keypair management
 */

package kdc

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
)

// KdcJoseKeys manages the KDC's JOSE keypair
type KdcJoseKeys struct {
	PrivateKey      crypto.PrivateKey // JOSE private key (P-256 ECDSA)
	PublicKey       crypto.PublicKey  // JOSE public key
	PrivateKeyBytes []byte            // Serialized private key (JWK JSON)
	PublicKeyBytes  []byte            // Serialized public key (JWK JSON)
}

// GetKdcJoseKeypair loads the KDC JOSE keypair
// privKeyPath: Path to private key file (JWK format)
// Returns: KdcJoseKeys with both private and public keys
func GetKdcJoseKeypair(privKeyPath string) (*KdcJoseKeys, error) {
	// Try to load existing keypair from file
	if privKeyPath != "" {
		if keys, err := loadKdcJoseKeypair(privKeyPath); err == nil {
			log.Printf("KDC: Loaded JOSE keypair from %s", privKeyPath)
			return keys, nil
		} else {
			log.Printf("KDC: ERROR: Failed to load JOSE keypair from %s: %v", privKeyPath, err)
			log.Printf("KDC: ERROR: Cannot decrypt enrollment requests without the correct JOSE private key!")
			log.Printf("KDC: ERROR: Ensure kdc_jose_priv_key in KDC config points to the correct key file.")
			return nil, fmt.Errorf("failed to load JOSE keypair from %s: %v (cannot decrypt enrollment requests without the correct key)", privKeyPath, err)
		}
	}

	// No key path configured
	log.Printf("KDC: ERROR: kdc_jose_priv_key is not configured in KDC config")
	log.Printf("KDC: ERROR: Cannot decrypt enrollment requests without JOSE private key!")
	return nil, fmt.Errorf("kdc_jose_priv_key is not configured in KDC config - required for enrollment decryption")
}

// loadKdcJoseKeypair loads JOSE keypair from file
func loadKdcJoseKeypair(privKeyPath string) (*KdcJoseKeys, error) {
	// Read private key file
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	// Parse private key (skip comments, extract JSON)
	privKeyLines := strings.Split(string(privKeyData), "\n")
	var jwkJSON string
	for _, line := range privKeyLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			jwkJSON += line
		}
	}

	if jwkJSON == "" {
		return nil, fmt.Errorf("could not find private key JSON in file %s", privKeyPath)
	}

	// Parse JWK JSON
	backend, err := crypto.GetBackend("jose")
	if err != nil {
		return nil, fmt.Errorf("failed to get JOSE backend: %v", err)
	}

	// Parse private key using backend
	privKey, err := backend.ParsePrivateKey([]byte(jwkJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JOSE private key: %v", err)
	}

	// Extract public key from private JWK
	// A JWK private key has a 'd' parameter (private scalar) that we need to remove
	// to get the public key
	var privateJWKMap map[string]interface{}
	err = json.Unmarshal([]byte(jwkJSON), &privateJWKMap)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private JWK JSON: %v", err)
	}

	// Create public key version by removing the 'd' parameter (private scalar)
	delete(privateJWKMap, "d")
	publicJWKBytes, err := json.Marshal(privateJWKMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public JWK: %v", err)
	}

	// Parse public key using backend
	pubKey, err := backend.ParsePublicKey(publicJWKBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JOSE public key from private JWK: %v", err)
	}

	// Serialize keys for storage/transport
	privKeyBytes := []byte(jwkJSON)
	pubKeyBytes, err := backend.SerializePublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize JOSE public key: %v", err)
	}

	return &KdcJoseKeys{
		PrivateKey:      privKey,
		PublicKey:       pubKey,
		PrivateKeyBytes: privKeyBytes,
		PublicKeyBytes:  pubKeyBytes,
	}, nil
}

// saveKdcJoseKeypair saves JOSE keypair to file
// This function is intentionally unused but kept for future use.
//
//lint:ignore U1000 This function is kept for future use
func _saveKdcJoseKeypair(keys *KdcJoseKeys, privKeyPath string) error {
	// Serialize private key to JWK
	backend, err := crypto.GetBackend("jose")
	if err != nil {
		return fmt.Errorf("failed to get JOSE backend: %v", err)
	}

	privKeyJSON, err := backend.SerializePrivateKey(keys.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to serialize private key: %v", err)
	}

	// Parse JSON to pretty-print it
	var prettyJSON interface{}
	err = json.Unmarshal(privKeyJSON, &prettyJSON)
	if err != nil {
		return fmt.Errorf("failed to parse private key JSON: %v", err)
	}

	prettyJSONBytes, err := json.MarshalIndent(prettyJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format private key JSON: %v", err)
	}

	privKeyContent := fmt.Sprintf(`# KDC JOSE Private Key (P-256)
# Generated: %s
# Algorithm: P-256 (ECDSA for JWE with ECDH-ES)
# Format: JWK (JSON Web Key)
# Key Size: 256 bits (P-256 curve)
#
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
# This key is used by KDC to decrypt enrollment requests and other encrypted data.
#
%s
`, time.Now().Format(time.RFC3339), prettyJSONBytes)

	// Write private key file (readable/writable by owner only)
	if err := os.WriteFile(privKeyPath, []byte(privKeyContent), 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %v", err)
	}

	return nil
}

// GetKdcJosePubKey returns the KDC JOSE public key (serialized as JWK JSON)
// This is a convenience function that loads the keypair and returns the serialized public key
func GetKdcJosePubKey(privKeyPath string) ([]byte, error) {
	keys, err := GetKdcJoseKeypair(privKeyPath)
	if err != nil {
		return nil, err
	}
	return keys.PublicKeyBytes, nil
}
