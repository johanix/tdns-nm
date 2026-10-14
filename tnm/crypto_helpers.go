/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared cryptographic helper functions for TDNS Node Management
 * These functions abstract encryption/decryption operations and can be used
 * by both KDC and KRS components.
 */

package tnm

import (
	"fmt"
	"log"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Auto-register JOSE backend
)

// SelectBackend selects the crypto backend for a peer from its supported list:
// the forced backend when the list has it and it is available here, otherwise
// the first listed backend that is available here. An empty list means JOSE.
// A list with no available backend (such as a stored "hpke", from before JOSE
// was the only backend) is an error.
//
// Parameters:
//   - supportedCrypto: List of supported backends (e.g., []string{"jose"})
//   - forcedCrypto: Optional backend to force (e.g. "jose"); empty string auto-selects
func SelectBackend(supportedCrypto []string, forcedCrypto string) (string, error) {
	if len(supportedCrypto) == 0 {
		return "jose", nil
	}

	// If forced crypto is specified, use it if supported and available
	if forcedCrypto != "" {
		for _, supported := range supportedCrypto {
			if supported == forcedCrypto && crypto.IsBackendRegistered(forcedCrypto) {
				return forcedCrypto, nil
			}
		}
		// Forced crypto not usable - fall through to auto-select
		log.Printf("TNM: Warning: Forced crypto backend %s not in supported list %v or not available, auto-selecting instead", forcedCrypto, supportedCrypto)
	}

	// Use the first supported backend that is available
	for _, name := range supportedCrypto {
		if crypto.IsBackendRegistered(name) {
			return name, nil
		}
	}
	return "", fmt.Errorf("none of the supported crypto backends %v is available", supportedCrypto)
}

// ExtractEphemeralKey extracts the ephemeral public key from ciphertext using the backend's GetEphemeralKey method.
// This is a helper function that standardizes the pattern of calling GetEphemeralKey and handling nil returns.
// Returns the ephemeral key bytes (or empty slice if backend returns nil, e.g., for JOSE where key is in JWE header).
func ExtractEphemeralKey(backend crypto.Backend, ciphertext []byte) ([]byte, error) {
	ephemeralPub, err := backend.GetEphemeralKey(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ephemeral key from ciphertext: %v", err)
	}
	// If backend returns nil (e.g., JOSE where ephemeral key is in JWE header),
	// convert to empty slice for consistency
	if ephemeralPub == nil {
		ephemeralPub = []byte{}
	}
	return ephemeralPub, nil
}

// EncryptPayload encrypts an arbitrary plaintext payload using the specified crypto backend.
// This is the core encryption function that abstracts crypto backend selection and encryption
// from operation-specific logic. Both KDC and KRS can use this function.
//
// Parameters:
//   - plaintext: The unencrypted payload to encrypt (operation-agnostic)
//   - publicKeyData: Raw public key bytes (JOSE: JWK JSON bytes)
//   - backendName: The crypto backend to use (e.g. "jose")
//   - supportedCrypto: Optional list of supported backends (for validation); can be nil
//   - context: Optional context string for logging (e.g., "node ID" or "KDC")
//
// Returns:
//   - ciphertext: The encrypted payload
//   - ephemeralPub: Ephemeral public key (empty for JOSE, where it is in the JWE header)
//   - error: Any error during encryption
func EncryptPayload(plaintext []byte, publicKeyData []byte, backendName string, supportedCrypto []string, context string) (ciphertext []byte, ephemeralPub []byte, err error) {
	if len(plaintext) == 0 {
		return nil, nil, fmt.Errorf("plaintext is nil or empty")
	}
	if len(publicKeyData) == 0 {
		return nil, nil, fmt.Errorf("public key data is nil or empty")
	}
	if backendName == "" {
		return nil, nil, fmt.Errorf("backend name is empty")
	}

	// Validate backend is supported if supportedCrypto list is provided
	if len(supportedCrypto) > 0 {
		found := false
		for _, supported := range supportedCrypto {
			if supported == backendName {
				found = true
				break
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("backend %s not in supported crypto list %v", backendName, supportedCrypto)
		}
	}

	// Get crypto backend
	backend, err := crypto.GetBackend(backendName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get crypto backend %s: %v", backendName, err)
	}

	logCtx := context
	if logCtx == "" {
		logCtx = "payload"
	}
	log.Printf("TNM: Encrypting %s using %s backend", logCtx, backendName)

	// Parse public key using the selected backend
	publicKey, err := backend.ParsePublicKey(publicKeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key with %s backend: %v", backendName, err)
	}

	// Encrypt the plaintext using the backend
	ciphertext, err = backend.Encrypt(publicKey, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt payload with %s backend: %v", backendName, err)
	}

	// Extract ephemeral public key using backend-agnostic method
	// This abstracts backend-specific ciphertext format knowledge
	ephemeralPub, err = ExtractEphemeralKey(backend, ciphertext)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("TNM: Successfully encrypted %s using %s backend (ciphertext length: %d)", logCtx, backendName, len(ciphertext))
	return ciphertext, ephemeralPub, nil
}
