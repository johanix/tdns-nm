/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Crypto entry points: key encryption and chunk preparation through the crypto
 * abstraction layer
 */

package kdc

import (
	"fmt"
	"log"

	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Auto-register JOSE backend
)

// EncryptKeyForNode encrypts a DNSSEC key's private key material for a specific node.
//
// Returns: encrypted key data, ephemeral public key used, distribution ID, error
// This function also stores the distribution record in the database
// kdcConf is optional - if provided, expires_at will be set based on DistributionTTL
// distributionID is optional - if provided, uses that ID; otherwise generates one for this key
// forcedCrypto is optional - if provided (e.g. "jose"), forces that backend; otherwise auto-selects
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
	// Select backend for this node
	backendName := selectBackendForNode(node, forcedCrypto)
	backend, err := crypto.GetBackend(backendName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get crypto backend %s: %v", backendName, err)
	}

	log.Printf("KDC: Selected %s backend for node %s", backendName, node.ID)
	return kdc.EncryptKeyForNodeV2(key, node, backend, kdcConf, distributionID...)
}

// prepareChunksForNode prepares chunks for a node's distribution event.
// This is called on-demand when CHUNK is queried.
func (kdc *KdcDB) prepareChunksForNode(
	nodeID, distributionID string,
	conf *tnm.KdcConf,
) (*preparedChunks, error) {
	return kdc.prepareChunksForNodeV2(nodeID, distributionID, conf)
}
