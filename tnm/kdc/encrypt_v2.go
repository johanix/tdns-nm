/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE encryption functions for key distribution (V2 - crypto abstraction)
 * This is the v2 implementation using the crypto abstraction layer.
 * The v1 implementation (encrypt.go) remains unchanged for backward compatibility.
 */

package kdc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-transport/v2/crypto"
)

// EncryptKeyForNodeV2 encrypts a DNSSEC key's private key material for a specific node
// using the provided crypto backend (HPKE or JOSE).
// This is the v2 implementation using crypto abstraction.
// Returns: encrypted key data, ephemeral public key used (backend-specific), distribution ID, error
// This function also stores the distribution record in the database
// kdcConf is optional - if provided, expires_at will be set based on DistributionTTL
// distributionID is optional - if provided, uses that ID; otherwise generates one for this key
// backend specifies which crypto backend to use (hpke or jose)
func (kdc *KdcDB) EncryptKeyForNodeV2(
	key *DNSSECKey,
	node *Node,
	backend crypto.Backend,
	kdcConf *tnm.KdcConf,
	distributionID ...string,
) (encryptedKey []byte, ephemeralPubKey []byte, distID string, err error) {
	if key == nil {
		return nil, nil, "", fmt.Errorf("key is nil")
	}
	if node == nil {
		return nil, nil, "", fmt.Errorf("node is nil")
	}
	if backend == nil {
		return nil, nil, "", fmt.Errorf("backend is nil")
	}

	// Use provided distribution ID, or get/create one for this key
	if len(distributionID) > 0 && distributionID[0] != "" {
		distID = distributionID[0]
	} else {
		distID, err = kdc.GetOrCreateDistributionID(key.ZoneName, key)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to get/create distribution ID: %v", err)
		}
	}

	// Parse node's public key using the backend
	// Select the appropriate key based on backend type
	var nodePubKeyData []byte
	if backend.Name() == "jose" {
		if len(node.LongTermJosePubKey) == 0 {
			return nil, nil, "", fmt.Errorf("node %s does not have a JOSE public key stored (required for %s backend)", node.ID, backend.Name())
		}
		nodePubKeyData = node.LongTermJosePubKey
	} else {
		// Defensive check: refuse HPKE operations for JOSE-only nodes
		if len(node.SupportedCrypto) == 1 && node.SupportedCrypto[0] == "jose" {
			return nil, nil, "", fmt.Errorf("node %s only supports JOSE crypto backend, cannot use %s", node.ID, backend.Name())
		}
		if len(node.LongTermHpkePubKey) == 0 {
			return nil, nil, "", fmt.Errorf("node %s does not have a public key stored (required for %s backend)", node.ID, backend.Name())
		}
		nodePubKeyData = node.LongTermHpkePubKey
	}
	nodePubKey, err := backend.ParsePublicKey(nodePubKeyData)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to parse node public key with %s backend: %v", backend.Name(), err)
	}

	// Encrypt the private key using the backend
	ciphertext, err := backend.Encrypt(nodePubKey, key.PrivateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to encrypt key with %s backend: %v", backend.Name(), err)
	}

	// Extract ephemeral public key using backend-agnostic method
	// This abstracts backend-specific ciphertext format knowledge
	ephemeralPub, err := tnm.ExtractEphemeralKey(backend, ciphertext)
	if err != nil {
		return nil, nil, "", err
	}

	// Generate a unique ID for this distribution record
	distRecordID := make([]byte, 16)
	if _, err := rand.Read(distRecordID); err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate distribution record ID: %v", err)
	}
	distRecordIDHex := hex.EncodeToString(distRecordID)

	// Calculate expires_at based on DistributionTTL if config is provided
	var expiresAt *time.Time
	if kdcConf != nil {
		ttl := kdcConf.GetDistributionTTL()
		if ttl > 0 {
			expires := time.Now().Add(ttl)
			expiresAt = &expires
		}
	}

	// Store the distribution record in the database
	distRecord := &DistributionRecord{
		ID:              distRecordIDHex,
		ZoneName:        key.ZoneName,
		KeyID:           key.ID,
		NodeID:          node.ID,
		EncryptedKey:    ciphertext,
		EphemeralPubKey: ephemeralPub,
		CreatedAt:       time.Now(),
		ExpiresAt:       expiresAt,
		Status:          DistributionStatusPending,
		DistributionID:  distID,
		Operation:       "roll_key",
		Payload:         make(map[string]interface{}),
	}

	if err := kdc.AddDistributionRecord(distRecord); err != nil {
		return nil, nil, "", fmt.Errorf("failed to store distribution record: %v", err)
	}

	return ciphertext, ephemeralPub, distID, nil
}
