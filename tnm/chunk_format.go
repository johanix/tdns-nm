/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK format functions
 * DEPRECATED: Use github.com/johanix/tdns/v2/distrib instead
 */

package tnm

import (
	"github.com/johanix/tdns-transport/v2/distrib"
	"github.com/johanix/tdns/v2/core"
)

// ManifestData is re-exported from distrib for backward compatibility
// DEPRECATED: Use distrib.ManifestData instead
type ManifestData = distrib.ManifestData

// CreateCHUNKManifest creates a CHUNK manifest record from manifest data.
// DEPRECATED: Use distrib.CreateCHUNKManifest instead
func CreateCHUNKManifest(manifestData *ManifestData, format uint8) (*core.CHUNK, error) {
	return distrib.CreateCHUNKManifest(manifestData, format)
}

// ExtractManifestData extracts ManifestData from a CHUNK manifest record.
// DEPRECATED: Use distrib.ExtractManifestData instead
func ExtractManifestData(chunk *core.CHUNK) (*ManifestData, error) {
	return distrib.ExtractManifestData(chunk)
}

// CalculateCHUNKHMAC calculates HMAC-SHA256 for a CHUNK manifest record.
// DEPRECATED: Use distrib.CalculateCHUNKHMAC instead
func CalculateCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) error {
	return distrib.CalculateCHUNKHMAC(chunk, hmacKey)
}

// VerifyCHUNKHMAC verifies the HMAC-SHA256 for a CHUNK manifest record.
// DEPRECATED: Use distrib.VerifyCHUNKHMAC instead
func VerifyCHUNKHMAC(chunk *core.CHUNK, hmacKey []byte) (bool, error) {
	return distrib.VerifyCHUNKHMAC(chunk, hmacKey)
}
