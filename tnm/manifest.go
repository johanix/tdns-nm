/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared manifest creation helper functions
 * DEPRECATED: Use github.com/johanix/tdns/v2/distrib instead
 */

package tnm

import (
	"github.com/johanix/tdns-transport/v2/distrib"
)

// CreateManifestMetadata creates base metadata for a distribution manifest
// DEPRECATED: Use distrib.CreateManifestMetadata instead
func CreateManifestMetadata(contentType, distributionID, nodeID string, extraFields map[string]interface{}) map[string]interface{} {
	return distrib.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)
}

// ShouldIncludePayloadInline determines if a payload should be included inline in the manifest
// DEPRECATED: Use distrib.ShouldIncludePayloadInline instead
func ShouldIncludePayloadInline(payloadSize, estimatedTotalSize int) bool {
	return distrib.ShouldIncludePayloadInline(payloadSize, estimatedTotalSize)
}

// EstimateManifestSize estimates the size of a CHUNK manifest with the given metadata and payload
// DEPRECATED: Use distrib.EstimateManifestSize instead
func EstimateManifestSize(metadata map[string]interface{}, payload []byte) int {
	return distrib.EstimateManifestSize(metadata, payload)
}
