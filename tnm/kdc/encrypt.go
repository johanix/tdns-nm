/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE encryption functions for key distribution
 */

package kdc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-transport/v2/hpke"
)

// EncryptKeyForNodeV1 encrypts a DNSSEC key's private key material for a specific node
// using HPKE with the node's long-term public key (V1 implementation)
// Returns: encrypted key data, ephemeral public key used, distribution ID, error
// This function also stores the distribution record in the database
// kdcConf is optional - if provided, expires_at will be set based on DistributionTTL
// distributionID is optional - if provided, uses that ID; otherwise generates one for this key
func (kdc *KdcDB) EncryptKeyForNodeV1(key *DNSSECKey, node *Node, kdcConf *tnm.KdcConf, distributionID ...string) (encryptedKey []byte, ephemeralPubKey []byte, distID string, err error) {
	if key == nil {
		return nil, nil, "", fmt.Errorf("key is nil")
	}
	if node == nil {
		return nil, nil, "", fmt.Errorf("node is nil")
	}
	// Defensive check: refuse HPKE operations for JOSE-only nodes
	if len(node.SupportedCrypto) == 1 && node.SupportedCrypto[0] == "jose" {
		return nil, nil, "", fmt.Errorf("node %s only supports JOSE crypto backend, cannot use HPKE", node.ID)
	}
	if node.LongTermHpkePubKey == nil || len(node.LongTermHpkePubKey) != 32 {
		return nil, nil, "", fmt.Errorf("node long-term public key must be 32 bytes (got %d)", len(node.LongTermHpkePubKey))
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

	// Encrypt the private key using HPKE
	// Note: HPKE Base mode generates its own ephemeral key internally
	ciphertext, ephemeralPub, err := hpke.Encrypt(node.LongTermHpkePubKey, nil, key.PrivateKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to encrypt key: %v", err)
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
