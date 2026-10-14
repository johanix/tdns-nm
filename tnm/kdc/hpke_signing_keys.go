/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC HPKE signing keypair management (P-256 ECDSA)
 *
 * HPKE uses X25519 for encryption, which cannot perform ECDSA signatures.
 * This file manages a separate P-256 ECDSA keypair used for signing HPKE distributions.
 */

package kdc

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/johanix/tdns-nm/tnm/crypto/hpke"
	"github.com/johanix/tdns-transport/v2/crypto"
)

// KdcHpkeSigningKeys manages the KDC's HPKE signing keypair (P-256 ECDSA)
type KdcHpkeSigningKeys struct {
	PrivateKey      crypto.PrivateKey // P-256 ECDSA private key (signing)
	PublicKey       crypto.PublicKey  // P-256 ECDSA public key (verification)
	PrivateKeyBytes []byte            // Serialized private key (JWK JSON)
	PublicKeyBytes  []byte            // Serialized public key (JWK JSON)
}

// GetKdcHpkeSigningKeypair loads the KDC HPKE signing keypair
// privKeyPath: Path to private key file (JWK format for P-256)
// Returns: KdcHpkeSigningKeys with both private and public keys
func GetKdcHpkeSigningKeypair(privKeyPath string) (*KdcHpkeSigningKeys, error) {
	// Try to load existing keypair from file
	if privKeyPath != "" {
		if keys, err := loadKdcHpkeSigningKeypair(privKeyPath); err == nil {
			log.Printf("KDC: Loaded HPKE signing keypair from %s", privKeyPath)
			return keys, nil
		} else {
			log.Printf("KDC: ERROR: Failed to load HPKE signing keypair from %s: %v", privKeyPath, err)
			log.Printf("KDC: ERROR: Cannot sign HPKE distributions without the correct signing private key!")
			log.Printf("KDC: ERROR: Ensure kdc_hpke_signing_key in KDC config points to the correct key file.")
			return nil, fmt.Errorf("failed to load HPKE signing keypair from %s: %v (cannot sign distributions without the correct key)", privKeyPath, err)
		}
	}

	// No key path configured
	log.Printf("KDC: ERROR: kdc_hpke_signing_key is not configured in KDC config")
	log.Printf("KDC: ERROR: Cannot sign HPKE distributions without signing private key!")
	return nil, fmt.Errorf("kdc_hpke_signing_key is not configured in KDC config - required for signed HPKE distributions")
}

// loadKdcHpkeSigningKeypair loads HPKE signing keypair from file (P-256 JWK format)
func loadKdcHpkeSigningKeypair(privKeyPath string) (*KdcHpkeSigningKeys, error) {
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

	// Parse JWK JSON using HPKE backend (which has P-256 signing support)
	genericBackend, err := crypto.GetBackend("hpke")
	if err != nil {
		return nil, fmt.Errorf("failed to get HPKE backend: %v", err)
	}

	// Cast to HPKE backend to access signing key methods
	backend, ok := genericBackend.(*hpke.Backend)
	if !ok {
		return nil, fmt.Errorf("backend is not HPKE backend")
	}

	// Parse private key as signing key (P-256 ECDSA)
	privKey, err := backend.ParseSigningKey([]byte(jwkJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HPKE signing private key: %v", err)
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
	pubKey, err := backend.ParseVerifyKey(publicJWKBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HPKE signing public key from private JWK: %v", err)
	}

	// Serialize keys for storage/transport
	privKeyBytes := []byte(jwkJSON)
	pubKeyBytes, err := backend.SerializeVerifyKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HPKE signing public key: %v", err)
	}

	return &KdcHpkeSigningKeys{
		PrivateKey:      privKey,
		PublicKey:       pubKey,
		PrivateKeyBytes: privKeyBytes,
		PublicKeyBytes:  pubKeyBytes,
	}, nil
}

// GetKdcHpkeSigningPubKey returns the KDC HPKE signing public key (serialized as JWK JSON)
// This is a convenience function that loads the keypair and returns the serialized public key
func GetKdcHpkeSigningPubKey(privKeyPath string) ([]byte, error) {
	keys, err := GetKdcHpkeSigningKeypair(privKeyPath)
	if err != nil {
		return nil, err
	}
	return keys.PublicKeyBytes, nil
}
