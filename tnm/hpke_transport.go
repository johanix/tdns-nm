/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared HPKE encryption/decryption transport functions
 * Handles the ephemeralPub + ciphertext format used for transport
 */

package tnm

import (
	"encoding/base64"
	"fmt"

	"github.com/johanix/tdns-transport/v2/hpke"
)

// EncryptAndEncode encrypts plaintext using HPKE and encodes it for transport
// The transport format is: base64(<ephemeralPub (32 bytes)><ciphertext>)
// where ciphertext from hpke.Encrypt is: <encapsulated_key (32 bytes)><encrypted_data>
// For X25519, ephemeralPub == encapsulated_key, so we prepend it for compatibility
func EncryptAndEncode(recipientPubKey []byte, plaintext []byte) ([]byte, error) {
	if len(recipientPubKey) != 32 {
		return nil, fmt.Errorf("recipient public key must be 32 bytes (got %d)", len(recipientPubKey))
	}

	// Encrypt using HPKE
	ciphertext, ephemeralPub, err := hpke.Encrypt(recipientPubKey, nil, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %v", err)
	}

	// Combine ephemeral public key and ciphertext for transport
	// Format: <ephemeral_pub_key (32 bytes)><ciphertext>
	// Note: For X25519, ephemeralPub == encapsulated_key (they're the same)
	// We prepend ephemeralPub for compatibility with existing code
	encryptedData := append(ephemeralPub, ciphertext...)

	// Base64 encode the encrypted data
	base64Data := []byte(base64.StdEncoding.EncodeToString(encryptedData))

	return base64Data, nil
}

// DecodeAndDecrypt decodes base64-encoded encrypted data and decrypts it using HPKE
// The transport format is: base64(<ephemeralPub (32 bytes)><ciphertext>)
// where ciphertext from hpke.Encrypt is: <encapsulated_key (32 bytes)><encrypted_data>
// We skip the first 32 bytes (duplicate ephemeralPub) and pass the rest to hpke.Decrypt
func DecodeAndDecrypt(privateKey []byte, base64Data []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes (got %d)", len(privateKey))
	}

	// Decode base64 to get encrypted data
	encryptedData, err := base64.StdEncoding.DecodeString(string(base64Data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 encrypted data: %v", err)
	}

	// Format from KDC: <ephemeral_pub_key (32 bytes)><ciphertext>
	// Where ciphertext from hpke.Encrypt is: <encapsulated_key (32 bytes)><encrypted_data>
	// Note: For X25519, ephemeralPub == encapsulated_key (they're the same)
	// So the format is: <ephemeralPub (32 bytes)><encapsulated_key (32 bytes)><encrypted_data>
	// We need to skip the first 32 bytes (duplicate ephemeralPub) and pass the rest to hpke.Decrypt
	if len(encryptedData) < 64 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes (expected at least 64: 32 for ephemeral + 32 for encapsulated key)", len(encryptedData))
	}

	// Extract the actual ciphertext (skip first 32 bytes which is duplicate ephemeralPub)
	// The ciphertext from hpke.Encrypt already includes the encapsulated key
	actualCiphertext := encryptedData[32:]

	// Decrypt using HPKE
	// hpke.Decrypt expects: <encapsulated_key (32 bytes)><encrypted_data>
	plaintext, err := hpke.Decrypt(privateKey, nil, actualCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}
