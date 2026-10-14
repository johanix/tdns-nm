/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC HPKE keypair management
 */

package kdc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/hpke"
)

// KdcHpkeKeys manages the KDC's HPKE keypair
type KdcHpkeKeys struct {
	PrivateKey []byte // X25519 private key (32 bytes)
	PublicKey  []byte // X25519 public key (32 bytes)
}

// GetKdcHpkeKeypair loads or generates the KDC HPKE keypair
// privKeyPath: Path to private key file (if exists, loads from file; if not, generates new)
// Returns: KdcHpkeKeys with both private and public keys
func GetKdcHpkeKeypair(privKeyPath string) (*KdcHpkeKeys, error) {
	// Try to load existing keypair from file
	if privKeyPath != "" {
		if keys, err := loadKdcHpkeKeypair(privKeyPath); err == nil {
			log.Printf("KDC: Loaded HPKE keypair from %s", privKeyPath)
			return keys, nil
		} else {
			log.Printf("KDC: ERROR: Failed to load HPKE keypair from %s: %v", privKeyPath, err)
			log.Printf("KDC: ERROR: Cannot decrypt enrollment requests without the correct HPKE private key!")
			log.Printf("KDC: ERROR: The enrollment blob was encrypted with a different public key.")
			log.Printf("KDC: ERROR: Ensure kdc_hpke_priv_key in KDC config points to the correct key file.")
			// Don't generate a new keypair - this would break decryption
			return nil, fmt.Errorf("failed to load HPKE keypair from %s: %v (cannot decrypt enrollment requests without the correct key)", privKeyPath, err)
		}
	}

	// No key path configured
	log.Printf("KDC: ERROR: kdc_hpke_priv_key is not configured in KDC config")
	log.Printf("KDC: ERROR: Cannot decrypt enrollment requests without HPKE private key!")
	return nil, fmt.Errorf("kdc_hpke_priv_key is not configured in KDC config - required for enrollment decryption")
}

// loadKdcHpkeKeypair loads HPKE keypair from file
func loadKdcHpkeKeypair(privKeyPath string) (*KdcHpkeKeys, error) {
	// Read private key file
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	// Parse private key (skip comments, decode hex)
	privKeyLines := strings.Split(string(privKeyData), "\n")
	var privKeyHex string
	for _, line := range privKeyLines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			privKeyHex += line
		}
	}

	if privKeyHex == "" {
		return nil, fmt.Errorf("could not find private key in file %s", privKeyPath)
	}

	privKey, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex private key: %v", err)
	}

	if len(privKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes (got %d)", len(privKey))
	}

	// Derive public key from private key
	pubKey, err := hpke.DerivePublicKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %v", err)
	}

	return &KdcHpkeKeys{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// saveKdcHpkeKeypair saves HPKE keypair to file
// This function is intentionally unused but kept for future use.
//
//lint:ignore U1000 This function is kept for future use
func _saveKdcHpkeKeypair(keys *KdcHpkeKeys, privKeyPath string) error {
	// Format private key as hex with comments
	privKeyHex := hex.EncodeToString(keys.PrivateKey)
	pubKeyHex := hex.EncodeToString(keys.PublicKey)

	privKeyContent := fmt.Sprintf(`# KDC HPKE Private Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
# This key is used by KDC to decrypt enrollment requests and other encrypted data.
#
# Public Key: %s
#
%s
`, time.Now().Format(time.RFC3339), pubKeyHex, privKeyHex)

	// Write private key file (readable/writable by owner only)
	if err := os.WriteFile(privKeyPath, []byte(privKeyContent), 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %v", err)
	}

	return nil
}

// GetKdcHpkePubKey returns the KDC HPKE public key
// This is a convenience function that loads the keypair and returns just the public key
func GetKdcHpkePubKey(privKeyPath string) ([]byte, error) {
	keys, err := GetKdcHpkeKeypair(privKeyPath)
	if err != nil {
		return nil, err
	}
	return keys.PublicKey, nil
}

// GenerateKeyID generates a keyid from public key bytes using SHA-256
// Format: {algorithm}_{hash8} where hash8 is first 8 hex characters of SHA256 hash
// Example: "hpke_a1b2c3d4", "jose_e5f6a7b8"
func GenerateKeyID(algorithm string, publicKeyBytes []byte) string {
	hash := sha256.Sum256(publicKeyBytes)
	// Use first 4 bytes (8 hex chars) for a shorter, still collision-resistant keyid
	return fmt.Sprintf("%s_%x", algorithm, hash[:4])
}
