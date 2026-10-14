/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC-specific payload encryption wrapper for operations (ping, delete_key, node_components, etc.)
 * This is a convenience wrapper around the shared tnm.EncryptPayload function that works
 * with KDC Node structs.
 */

package kdc

import (
	"fmt"

	tnm "github.com/johanix/tdns-nm/tnm"
)

// EncryptPayloadForNode encrypts an arbitrary plaintext payload for a specific node.
// This is a convenience wrapper around tnm.EncryptPayload that extracts the public key
// from a Node struct and handles backend selection based on node capabilities.
//
// Parameters:
//   - node: The target node (must have appropriate public keys configured)
//   - plaintext: The unencrypted payload to encrypt (operation-agnostic)
//   - forcedCrypto: Optional backend to force (e.g. "jose"); empty string auto-selects
//
// Returns:
//   - ciphertext: The encrypted payload
//   - ephemeralPub: Ephemeral public key (empty for JOSE, where it is in the JWE header)
//   - backendName: The backend actually used (e.g. "jose")
//   - error: Any error during encryption
func EncryptPayloadForNode(node *Node, plaintext []byte, forcedCrypto string) (ciphertext []byte, ephemeralPub []byte, backendName string, err error) {
	if node == nil {
		return nil, nil, "", fmt.Errorf("node is nil")
	}

	// Select crypto backend based on node capabilities and forced preference
	backendName = selectBackendForNode(node, forcedCrypto)

	// Extract node's public key based on selected backend
	var nodePubKeyData []byte
	if backendName == "jose" {
		if len(node.LongTermJosePubKey) == 0 {
			return nil, nil, "", fmt.Errorf("node %s does not have a JOSE public key stored (required for %s backend)", node.ID, backendName)
		}
		nodePubKeyData = node.LongTermJosePubKey
	} else {
		return nil, nil, "", fmt.Errorf("unsupported crypto backend: %s", backendName)
	}

	// Use shared encryption function
	ciphertext, ephemeralPub, err = tnm.EncryptPayload(plaintext, nodePubKeyData, backendName, node.SupportedCrypto, fmt.Sprintf("node %s", node.ID))
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to encrypt payload for node %s: %v", node.ID, err)
	}

	return ciphertext, ephemeralPub, backendName, nil
}
