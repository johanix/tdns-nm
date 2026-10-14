/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Crypto abstraction decryption for tdns-krs (V2)
 * This is the v2 implementation using the crypto abstraction layer.
 * The v1 implementation (decrypt.go) remains unchanged for backward compatibility.
 */

package krs

import (
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns-transport/v2/crypto"
)

// DecryptAndStoreKeyV2 decrypts encrypted key data using crypto abstraction layer
// and stores the key in the database.
// The backend parameter specifies which crypto backend to use (hpke or jose).
// ephemeralPrivKey is currently unused but reserved for future use (e.g., for backends that require it).
func DecryptAndStoreKeyV2(
	krsDB *KrsDB,
	encryptedKey []byte,
	_ephemeralPrivKey []byte, // Reserved for future use; currently unused
	longTermPrivKey []byte,
	backend crypto.Backend,
	distributionID, zoneID string,
) error {
	if backend == nil {
		return fmt.Errorf("backend is nil")
	}

	// Parse the long-term private key using the backend
	privKey, err := backend.ParsePrivateKey(longTermPrivKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key with %s backend: %v", backend.Name(), err)
	}

	// Decrypt using the crypto backend
	plaintext, err := backend.Decrypt(privKey, encryptedKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt key with %s backend: %v", backend.Name(), err)
	}

	log.Printf("KRS: Successfully decrypted key for distribution %s, zone %s using %s backend (size: %d bytes)",
		distributionID, zoneID, backend.Name(), len(plaintext))

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

	log.Printf("KRS: Stored key for distribution %s, zone %s (decrypted with %s)", distributionID, zoneID, backend.Name())
	return nil
}
