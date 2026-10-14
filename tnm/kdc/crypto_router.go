/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Crypto routing layer - routes between v1 (direct HPKE) and v2 (crypto abstraction)
 * based on feature flag configuration
 */

package kdc

import (
	"fmt"
	"log"

	tnm "github.com/johanix/tdns-nm/tnm"
	_ "github.com/johanix/tdns-nm/tnm/crypto/hpke" // Auto-register HPKE backend
	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Auto-register JOSE backend
)

// EncryptKeyForNode encrypts a DNSSEC key's private key material for a specific node.
// This is a router function that checks the UseCryptoV2 feature flag and calls either:
// - V1: Direct HPKE implementation (encrypt.go)
// - V2: Crypto abstraction layer with backend selection (encrypt_v2.go)
//
// Returns: encrypted key data, ephemeral public key used, distribution ID, error
// This function also stores the distribution record in the database
// kdcConf is optional - if provided, expires_at will be set based on DistributionTTL
// distributionID is optional - if provided, uses that ID; otherwise generates one for this key
// forcedCrypto is optional - if provided ("hpke" or "jose"), forces that backend; otherwise auto-selects
func (kdc *KdcDB) EncryptKeyForNode(
	key *DNSSECKey,
	node *Node,
	kdcConf *tnm.KdcConf,
	distributionID ...string,
) (encryptedKey []byte, ephemeralPubKey []byte, distID string, err error) {
	return kdc.EncryptKeyForNodeWithCrypto(key, node, kdcConf, "", distributionID...)
}

// EncryptKeyForNodeWithCrypto is like EncryptKeyForNode but allows forcing a specific crypto backend
func (kdc *KdcDB) EncryptKeyForNodeWithCrypto(
	key *DNSSECKey,
	node *Node,
	kdcConf *tnm.KdcConf,
	forcedCrypto string,
	distributionID ...string,
) (encryptedKey []byte, ephemeralPubKey []byte, distID string, err error) {
	// Check feature flag
	if kdcConf != nil && kdcConf.ShouldUseCryptoV2() {
		// V2: Use crypto abstraction layer
		log.Printf("KDC: Using crypto V2 (abstraction layer) for key encryption")

		// Select backend for this node
		backendName := selectBackendForNode(node, forcedCrypto)
		backend, err := crypto.GetBackend(backendName)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to get crypto backend %s: %v", backendName, err)
		}

		log.Printf("KDC: Selected %s backend for node %s", backendName, node.ID)
		return kdc.EncryptKeyForNodeV2(key, node, backend, kdcConf, distributionID...)
	}

	// V1: Use direct HPKE implementation (default)
	// If forced crypto is JOSE, we can't use V1 - must use V2
	if forcedCrypto == "jose" {
		return nil, nil, "", fmt.Errorf("JOSE backend requires crypto V2 (use_crypto_v2 must be enabled)")
	}
	log.Printf("KDC: Using crypto V1 (direct HPKE) for key encryption")
	return kdc.EncryptKeyForNodeV1(key, node, kdcConf, distributionID...)
}

// prepareChunksForNode prepares chunks for a node's distribution event.
// This is a router function that checks the UseCryptoV2 feature flag and calls either:
// - V1: Direct HPKE implementation (chunks.go)
// - V2: Crypto abstraction layer with backend selection (chunks_v2.go)
//
// This is called on-demand when CHUNK is queried.
func (kdc *KdcDB) prepareChunksForNode(
	nodeID, distributionID string,
	conf *tnm.KdcConf,
) (*preparedChunks, error) {
	// Check feature flag
	if conf != nil && conf.ShouldUseCryptoV2() {
		// V2: Use crypto abstraction layer
		log.Printf("KDC: Using crypto V2 (abstraction layer) for chunk preparation")
		return kdc.prepareChunksForNodeV2(nodeID, distributionID, conf)
	}

	// V1: Use direct HPKE implementation (default)
	log.Printf("KDC: Using crypto V1 (direct HPKE) for chunk preparation")
	return kdc.prepareChunksForNodeV1(nodeID, distributionID, conf)
}
