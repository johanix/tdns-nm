/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Crypto routing layer for KRS - routes between v1 (direct HPKE) and v2 (crypto abstraction)
 * based on feature flag configuration
 */

package krs

import (
	"fmt"
	"log"

	tnm "github.com/johanix/tdns-nm/tnm"
	_ "github.com/johanix/tdns-nm/tnm/crypto/hpke" // Auto-register HPKE backend
	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Auto-register JOSE backend
)

// DecryptAndStoreKey decrypts encrypted key data and stores the key in the database.
// This is a router function that checks the UseCryptoV2 feature flag and calls either:
// - V1: Direct HPKE implementation (decrypt.go)
// - V2: Crypto abstraction layer with backend selection (decrypt_v2.go)
//
// The backend to use is determined from the CHUNK manifest metadata "crypto" field
// (handled by the caller - chunk handler in Session 8).
// For V2, the backend parameter must be provided by the caller.
func DecryptAndStoreKey(
	krsDB *KrsDB,
	encryptedKey []byte,
	ephemeralPrivKey []byte,
	longTermPrivKey []byte,
	distributionID, zoneID string,
	krsConf *tnm.KrsConf,
	backendName ...string, // Optional: backend name for V2 ("hpke" or "jose")
) error {
	// Check feature flag
	if krsConf != nil && krsConf.ShouldUseCryptoV2() {
		// V2: Use crypto abstraction layer
		log.Printf("KRS: Using crypto V2 (abstraction layer) for key decryption")

		// Determine backend to use
		var backend crypto.Backend
		var err error

		if len(backendName) > 0 && backendName[0] != "" {
			// Backend specified by caller (from manifest metadata)
			backend, err = crypto.GetBackend(backendName[0])
			if err != nil {
				return fmt.Errorf("failed to get crypto backend %s: %v", backendName[0], err)
			}
			log.Printf("KRS: Using %s backend (from manifest metadata)", backendName[0])
		} else {
			// Default to HPKE for backward compatibility
			backend, err = crypto.GetBackend("hpke")
			if err != nil {
				return fmt.Errorf("failed to get HPKE backend: %v", err)
			}
			log.Printf("KRS: Using default HPKE backend (no backend specified in manifest)")
		}

		return DecryptAndStoreKeyV2(krsDB, encryptedKey, ephemeralPrivKey, longTermPrivKey, backend, distributionID, zoneID)
	}

	// V1: Use direct HPKE implementation (default)
	log.Printf("KRS: Using crypto V1 (direct HPKE) for key decryption")
	return DecryptAndStoreKeyV1(krsDB, encryptedKey, ephemeralPrivKey, longTermPrivKey, distributionID, zoneID)
}
