/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * HPKE decryption and key storage for tdns-krs
 */

package krs

import (
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns-transport/v2/hpke"
)

// DecryptAndStoreKeyV1 decrypts encrypted key data using HPKE and stores the key in the database (V1 implementation)
func DecryptAndStoreKeyV1(krsDB *KrsDB, encryptedKey []byte, ephemeralPrivKey []byte, longTermPrivKey []byte, distributionID, zoneID string) error {
	// Decrypt using HPKE
	// The encryptedKey contains the encapsulated key + ciphertext
	// We use the long-term private key to decrypt
	plaintext, err := hpke.Decrypt(longTermPrivKey, nil, encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %v", err)
	}

	// TODO: Parse the decrypted plaintext as a DNSSEC private key (PEM format)
	// For now, we'll store it as-is
	log.Printf("KRS: Successfully decrypted key for distribution %s, zone %s (size: %d bytes)", distributionID, zoneID, len(plaintext))

	// TODO: Parse the decrypted plaintext as a DNSSEC private key (PEM format) to extract metadata
	// TODO: Alternatively, extract KeyType, Algorithm, Flags, PublicKey, and KeyID from distribution record metadata
	// For now, we store the key with unknown metadata to avoid persisting misleading DNSKEY/DS material
	// The metadata should be populated from the distribution record or parsed from the plaintext before use
	key := &ReceivedKey{
		ID:             distributionID,
		ZoneName:       zoneID,    // zoneID parameter is actually zone name
		KeyID:          0,         // TODO: Extract from distribution record metadata or parse from plaintext
		KeyType:        "unknown", // TODO: Extract from distribution record metadata or parse from plaintext
		Algorithm:      0,         // TODO: Extract from distribution record metadata or parse from plaintext
		Flags:          0,         // TODO: Extract from distribution record metadata or parse from plaintext
		PublicKey:      "",        // TODO: Extract from distribution record metadata or parse from plaintext
		PrivateKey:     plaintext,
		State:          "received",
		ReceivedAt:     time.Now(),
		DistributionID: distributionID,
	}

	// Store in database
	if err := krsDB.AddReceivedKey(key); err != nil {
		return fmt.Errorf("failed to store received key: %v", err)
	}

	log.Printf("KRS: Stored key for distribution %s, zone %s", distributionID, zoneID)
	return nil
}
