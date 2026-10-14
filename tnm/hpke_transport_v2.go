/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared crypto abstraction encryption/decryption transport functions (V2)
 * DEPRECATED: Use github.com/johanix/tdns/v2/distrib instead
 */

package tnm

import (
	nmdistrib "github.com/johanix/tdns-nm/tnm/distrib"
	"github.com/johanix/tdns-transport/v2/crypto"
)

// EncryptAndEncodeV2 encrypts plaintext using the specified crypto backend and encodes it for transport
// DEPRECATED: Use EncryptAndEncode instead (note: parameter order differs)
func EncryptAndEncodeV2(recipientPubKey crypto.PublicKey, plaintext []byte, backend crypto.Backend) ([]byte, error) {
	return nmdistrib.EncryptAndEncode(backend, recipientPubKey, plaintext)
}

// DecodeAndDecryptV2 decodes base64-encoded encrypted data and decrypts it using the specified crypto backend
// DEPRECATED: Use DecodeAndDecrypt instead (note: parameter order differs)
func DecodeAndDecryptV2(privateKey crypto.PrivateKey, base64Data []byte, backend crypto.Backend) ([]byte, error) {
	return nmdistrib.DecodeAndDecrypt(backend, privateKey, base64Data)
}

// EncryptSignAndEncodeV2 encrypts plaintext and signs it, creating JWS(JWE(payload))
// DEPRECATED: Use EncryptSignAndEncode instead (note: parameter order differs)
func EncryptSignAndEncodeV2(recipientPubKey crypto.PublicKey, plaintext []byte, signingKey crypto.PrivateKey, backend crypto.Backend, metadata map[string]interface{}) ([]byte, error) {
	return nmdistrib.EncryptSignAndEncode(backend, recipientPubKey, plaintext, signingKey, metadata)
}

// DecodeDecryptAndVerifyV2 decodes, verifies signature, and decrypts JWS(JWE(payload))
// DEPRECATED: Use DecodeDecryptAndVerify instead (note: parameter order differs)
func DecodeDecryptAndVerifyV2(privateKey crypto.PrivateKey, verificationKey crypto.PublicKey, base64Data []byte, backend crypto.Backend) ([]byte, error) {
	return nmdistrib.DecodeDecryptAndVerify(backend, privateKey, verificationKey, base64Data)
}
