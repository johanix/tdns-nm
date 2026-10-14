/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Chunk preparation and retrieval for CHUNK queries (V2 - crypto abstraction)
 * This is the v2 implementation using the crypto abstraction layer.
 * The v1 implementation (chunks.go) remains unchanged for backward compatibility.
 */

package kdc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	nmdistrib "github.com/johanix/tdns-nm/tnm/distrib"
	"github.com/johanix/tdns-transport/v2/crypto"
	"github.com/johanix/tdns-transport/v2/distrib"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"

	tnm "github.com/johanix/tdns-nm/tnm"
)

// selectBackendForNode determines which crypto backend to use for a node
// based on the node's SupportedCrypto field.
// This is a convenience wrapper around tnm.SelectBackend that works with Node structs.
// forcedCrypto: if provided ("hpke" or "jose"), forces that backend (if node supports it)
// Returns the backend name (e.g., "hpke", "jose")
func selectBackendForNode(node *Node, forcedCrypto string) string {
	backendName := tnm.SelectBackend(node.SupportedCrypto, forcedCrypto)
	if forcedCrypto != "" && backendName != forcedCrypto {
		log.Printf("KDC: Warning: Node %s does not support forced crypto backend %s, auto-selected %s instead", node.ID, forcedCrypto, backendName)
	}
	return backendName
}

// determineContentType analyzes distribution records to determine the content type
// based on the operations present (node_operations, key_operations, mgmt_operations, or mixed_operations).
func determineContentType(records []*DistributionRecord) string {
	hasNodeOps := false // update_components
	hasKeyOps := false  // roll_key, delete_key
	hasMgmtOps := false // ping

	for _, record := range records {
		switch record.Operation {
		case "update_components":
			hasNodeOps = true
		case "roll_key", "delete_key":
			hasKeyOps = true
		case "ping":
			hasMgmtOps = true
		}
	}

	// Determine contentType based on operation mix
	contentType := "key_operations" // default
	if hasNodeOps && !hasKeyOps && !hasMgmtOps {
		contentType = "node_operations"
	} else if !hasNodeOps && hasKeyOps && !hasMgmtOps {
		contentType = "key_operations"
	} else if !hasNodeOps && !hasKeyOps && hasMgmtOps {
		contentType = "mgmt_operations"
	} else if hasNodeOps || hasKeyOps || hasMgmtOps {
		contentType = "mixed_operations"
	}

	return contentType
}

// buildNodeOperationsPayload prepares the payload for node_operations (update_components).
// It returns the base64-encoded encrypted payload and metadata counts.
func (kdc *KdcDB) buildNodeOperationsPayload(
	nodeRecords []*DistributionRecord,
	distributionID string,
	backend crypto.Backend,
	backendName string,
	signingKey crypto.PrivateKey,
) ([]byte, int, int, error) {
	if len(nodeRecords) != 1 {
		return nil, 0, 0, fmt.Errorf("node_operations distribution should have exactly one record, got %d", len(nodeRecords))
	}

	record := nodeRecords[0]
	if record.Operation != "update_components" {
		return nil, 0, 0, fmt.Errorf("node_operations distribution has non-update_components operation: %s", record.Operation)
	}

	// The distribution record contains encrypted component list (JWE format)
	// For V2, this is already encrypted as JWE compact serialization
	jweData := record.EncryptedKey

	log.Printf("KDC: Using encrypted component list from distribution record: %d bytes (JWE format)",
		len(jweData))

	var base64Data []byte

	// If signing key is available, sign the JWE to create JWS(JWE)
	if signingKey != nil {
		log.Printf("KDC: Using signed encryption (JWS(JWE)) for node_operations with %s backend", backendName)

		// Sign the JWE to create JWS(JWE)
		jwsData, err := backend.Sign(signingKey, jweData)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("failed to sign node_operations JWE: %v", err)
		}

		log.Printf("KDC: Signed node_operations JWE: JWE %d bytes -> JWS(JWE) %d bytes",
			len(jweData), len(jwsData))

		// Base64 encode JWS(JWE) for transport
		base64Data = []byte(base64.StdEncoding.EncodeToString(jwsData))

		log.Printf("KDC: Signed and encoded node_operations distribution: JWS(JWE) %d bytes -> base64 %d bytes",
			len(jwsData), len(base64Data))
	} else {
		// No signing key - use unsigned distribution (JWE only, backward compatibility)
		log.Printf("KDC: Using unsigned encryption (JWE only) for node_operations with %s backend (no signing key)", backendName)

		// Base64 encode JWE for transport
		base64Data = []byte(base64.StdEncoding.EncodeToString(jweData))

		log.Printf("KDC: Unsigned node_operations distribution: JWE %d bytes -> base64 %d bytes",
			len(jweData), len(base64Data))
	}

	return base64Data, 0, 0, nil
}

// buildKeyOperationsPayload prepares the payload for key_operations, mgmt_operations, or mixed_operations.
// It builds the JSON structure, encrypts it, and returns the base64-encoded ciphertext with metadata counts.
// If signingKey is provided, creates JWS(JWE(...)) for authenticated distribution.
func (kdc *KdcDB) buildKeyOperationsPayload(
	nodeRecords []*DistributionRecord,
	distributionID string,
	nodeID string,
	backend crypto.Backend,
	backendName string,
	nodePubKey crypto.PublicKey,
	signingKey crypto.PrivateKey,
	encryptMetadata map[string]interface{},
) ([]byte, int, int, int, error) {
	// Prepare JSON structure with operation-based distribution entries
	entries := make([]tnm.DistributionEntry, 0, len(nodeRecords))
	zoneSet := make(map[string]bool)

	for _, record := range nodeRecords {
		entry := tnm.DistributionEntry{
			Operation: record.Operation,
			Metadata:  record.Payload,
		}

		switch record.Operation {
		case string(OperationRollKey):
			// Fetch key details from dnssec_keys table
			key, err := kdc.GetDNSSECKeyByID(record.ZoneName, record.KeyID)
			if err != nil {
				log.Printf("KDC: Warning: Failed to get key %s for zone %s: %v", record.KeyID, record.ZoneName, err)
				continue
			}

			// Populate entry with key details
			entry.ZoneName = record.ZoneName
			entry.KeyID = record.KeyID
			entry.KeyType = string(key.KeyType)
			entry.Algorithm = key.Algorithm
			entry.Flags = key.Flags
			entry.PublicKey = key.PublicKey
			entry.PrivateKey = base64.StdEncoding.EncodeToString(key.PrivateKey)

			zoneSet[record.ZoneName] = true

		case string(OperationPing):
			// Ping operation - metadata already contains nonce and timestamp
			// No additional fields needed

		case string(OperationDeleteKey):
			// Delete key operation
			entry.ZoneName = record.ZoneName
			entry.KeyID = record.KeyID
			zoneSet[record.ZoneName] = true

		default:
			log.Printf("KDC: Warning: Unknown operation type %q in distribution %s", record.Operation, distributionID)
			continue
		}

		entries = append(entries, entry)
	}

	operationCount := len(entries)
	keyCount := 0
	for _, entry := range entries {
		if entry.Operation == "roll_key" || entry.Operation == "delete_key" {
			keyCount++
		}
	}
	zoneCount := len(zoneSet)

	if operationCount == 0 {
		return nil, 0, 0, 0, fmt.Errorf("no valid operations found for node %s, distribution %s", nodeID, distributionID)
	}

	// Marshal to JSON (cleartext)
	entriesJSON, err := json.Marshal(entries)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("failed to marshal entries JSON: %v", err)
	}

	// Debug logging: log cleartext content (masking private keys)
	if tdns.Globals.Debug {
		// Create a copy for logging with masked private keys
		logEntries := make([]map[string]interface{}, len(entries))
		for i, entry := range entries {
			logEntry := map[string]interface{}{
				"operation": entry.Operation,
				"zone_name": entry.ZoneName,
				"key_id":    entry.KeyID,
			}
			if entry.Operation == string(OperationRollKey) {
				logEntry["key_type"] = entry.KeyType
				logEntry["algorithm"] = entry.Algorithm
				logEntry["flags"] = entry.Flags
				logEntry["public_key"] = entry.PublicKey
				logEntry["private_key"] = "***MASKED***"
			}
			if entry.Metadata != nil {
				logEntry["metadata"] = entry.Metadata
			}
			logEntries[i] = logEntry
		}
		logJSON, _ := json.Marshal(logEntries)
		log.Printf("KDC: DEBUG: Cleartext distribution payload (private keys masked): %s", string(logJSON))
	}

	log.Printf("KDC: Prepared %d operations (%d key ops) for %d zones, JSON size: %d bytes",
		operationCount, keyCount, zoneCount, len(entriesJSON))

	// Encrypt the payload - use signed encryption (JWS(JWE)) if signing key is provided
	var base64Data []byte
	if signingKey != nil {
		// Use signed encryption: JWS(JWE(payload))
		// This provides both confidentiality (JWE) and authenticity (JWS)
		log.Printf("KDC: Using signed encryption (JWS(JWE)) with %s backend", backendName)
		base64Data, err = nmdistrib.EncryptSignAndEncode(backend, nodePubKey, entriesJSON, signingKey, encryptMetadata)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("failed to encrypt and sign distribution payload with %s backend: %v", backendName, err)
		}
		log.Printf("KDC: Encrypted and signed distribution payload with %s: cleartext %d bytes -> JWS(JWE) %d bytes (base64)",
			backendName, len(entriesJSON), len(base64Data))
	} else {
		// Use traditional encryption (backward compatibility)
		log.Printf("KDC: Using traditional encryption (no signature) with %s backend", backendName)
		ciphertext, err := backend.Encrypt(nodePubKey, entriesJSON)
		if err != nil {
			return nil, 0, 0, 0, fmt.Errorf("failed to encrypt distribution payload with %s backend: %v", backendName, err)
		}
		// Base64 encode for transport
		base64Data = []byte(base64.StdEncoding.EncodeToString(ciphertext))
		log.Printf("KDC: Encrypted distribution payload with %s: cleartext %d bytes -> ciphertext %d bytes -> base64 %d bytes",
			backendName, len(entriesJSON), len(ciphertext), len(base64Data))
	}

	return base64Data, zoneCount, keyCount, operationCount, nil
}

// buildManifestMetadata creates manifest metadata with extra fields based on content type.
func buildManifestMetadata(
	contentType string,
	distributionID string,
	nodeID string,
	backendName string,
	zoneCount int,
	keyCount int,
	operationCount int,
	componentCount int,
	conf *tnm.KdcConf,
) map[string]interface{} {
	extraFields := make(map[string]interface{})
	if contentType == "key_operations" || contentType == "mgmt_operations" || contentType == "mixed_operations" {
		extraFields["zone_count"] = zoneCount
		extraFields["key_count"] = keyCount
		extraFields["operation_count"] = operationCount
	} else if contentType == "node_operations" {
		extraFields["component_count"] = componentCount
	}
	// Add retire_time from config if available
	if conf != nil && conf.RetireTime > 0 {
		extraFields["retire_time"] = conf.RetireTime.String()
	}
	// Add distribution_ttl from config if available (for KRS validation)
	if conf != nil && conf.GetDistributionTTL() > 0 {
		extraFields["distribution_ttl"] = conf.GetDistributionTTL().String()
	}
	// Add crypto backend to metadata
	extraFields["crypto"] = backendName

	return distrib.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)
}

// splitIntoChunks determines if payload should be included inline or split into chunks,
// and returns the chunk count, chunk size, and data chunks.
//
// Parameters:
//   - base64Data: The payload data (already base64-encoded)
//   - metadata: Manifest metadata (used for JSON format size estimation)
//   - jwtClaims: JWT claims template (used for JWT format size estimation, nil for JSON format)
//   - conf: KDC configuration (provides max chunk size)
//
// The function uses the appropriate size estimator based on whether jwtClaims is provided:
//   - If jwtClaims != nil: Uses JWT format estimation (larger due to JWS overhead)
//   - If jwtClaims == nil: Uses JSON format estimation
func splitIntoChunks(
	base64Data []byte,
	metadata map[string]interface{},
	jwtClaims *nmdistrib.JWTManifestClaims,
	conf *tnm.KdcConf,
) (uint16, uint16, []*core.CHUNK, error) {
	// Get max chunk size from config (this is the inline threshold for TCP transport)
	const defaultChunkSize = 60000
	var maxSize int
	if conf != nil {
		maxSize = conf.GetChunkMaxSize()
	} else {
		maxSize = defaultChunkSize
	}

	// Estimate manifest size based on format
	var estimatedSize int
	var formatName string
	if jwtClaims != nil {
		// JWT format - use JWT estimator
		testClaims := *jwtClaims
		testClaims.Payload = base64.StdEncoding.EncodeToString(base64Data)
		estimatedSize = nmdistrib.EstimateJWTManifestSize(&testClaims)
		formatName = "JWT"
	} else {
		// JSON format - use JSON estimator
		estimatedSize = distrib.EstimateManifestSize(metadata, base64Data)
		formatName = "JSON"
	}

	// Determine if payload should be included inline
	includeInline := distrib.ShouldIncludePayloadInlineWithLimit(estimatedSize, maxSize)

	var dataChunks []*core.CHUNK
	var chunkCount uint16
	var chunkSize uint16

	if includeInline {
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Payload %d bytes, estimated %s manifest %d bytes (max %d) - including inline",
			len(base64Data), formatName, estimatedSize, maxSize)
	} else {
		dataChunks = distrib.SplitIntoCHUNKs(base64Data, maxSize, core.FormatJSON)
		// Check if SplitIntoCHUNKs returned nil (overflow condition)
		if dataChunks == nil {
			return 0, 0, nil, fmt.Errorf("failed to split data into chunks (overflow or invalid chunk size)")
		}
		// Check for integer overflow before converting to uint16
		if len(dataChunks) > math.MaxUint16 {
			return 0, 0, nil, fmt.Errorf("too many chunks: %d (max: %d)", len(dataChunks), math.MaxUint16)
		}
		if maxSize > math.MaxUint16 {
			return 0, 0, nil, fmt.Errorf("chunk size too large: %d (max: %d)", maxSize, math.MaxUint16)
		}
		if len(dataChunks) == 0 {
			return 0, 0, nil, fmt.Errorf("no chunks created from data (data may be empty)")
		}
		chunkCount = uint16(len(dataChunks))
		chunkSize = uint16(maxSize)
		log.Printf("KDC: Payload %d bytes, estimated %s manifest %d bytes (max %d) - splitting into %d chunks",
			len(base64Data), formatName, estimatedSize, maxSize, chunkCount)
	}

	return chunkCount, chunkSize, dataChunks, nil
}

// prepareChunksForNodeV2 prepares chunks for a node's distribution event
// using the crypto abstraction layer to support both HPKE and JOSE.
// This is called on-demand when CHUNK is queried.
// The crypto backend is selected based on the node's SupportedCrypto field.
//
// The function delegates to helper functions for better maintainability:
//   - determineContentType() - analyzes operations to determine content type
//   - buildNodeOperationsPayload() - handles node_operations
//   - buildKeyOperationsPayload() - handles key_operations, mgmt_operations, mixed_operations
//   - buildManifestMetadata() - creates manifest metadata with extra fields
//   - splitIntoChunks() - handles CHUNK splitting logic
func (kdc *KdcDB) prepareChunksForNodeV2(
	nodeID, distributionID string,
	conf *tnm.KdcConf,
) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first (use same cache as v1 for now)
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		// Debug: Check manifest chunk Data field in cached chunks
		if len(cached.chunks) > 0 && cached.chunks[0].Sequence == 0 {
			manifestChunk := cached.chunks[0]
			dataType := "unknown"
			if len(manifestChunk.Data) > 0 {
				if manifestChunk.Data[0] == '{' || manifestChunk.Data[0] == '[' {
					dataType = "JSON"
				} else {
					dataType = "base64"
				}
			}
			log.Printf("KDC: Using cached chunks for node %s, distribution %s (manifest data_type=%s, data_len=%d)",
				nodeID, distributionID, dataType, len(manifestChunk.Data))
		} else {
			log.Printf("KDC: Using cached chunks for node %s, distribution %s", nodeID, distributionID)
		}
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing chunks (v2) for node %s, distribution %s", nodeID, distributionID)

	// Get the node to determine backend and access public key
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
	}

	// Get all distribution records for this distributionID to check for stored crypto backend
	records, err := kdc.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution records: %v", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no distribution records found for distribution %s (may have been purged after completion)", distributionID)
	}

	// Check if any record has a stored crypto backend in its payload (for ping operations)
	var forcedCrypto string
	for _, record := range records {
		if record.Payload != nil {
			if cryptoBackend, ok := record.Payload["crypto"].(string); ok && cryptoBackend != "" {
				if forcedCrypto == "" {
					forcedCrypto = cryptoBackend
					log.Printf("KDC: Found stored crypto backend %s in distribution record payload", cryptoBackend)
				} else if forcedCrypto != cryptoBackend {
					log.Printf("KDC: Warning: Distribution %s has records with conflicting crypto backends (%s vs %s), using %s",
						distributionID, forcedCrypto, cryptoBackend, forcedCrypto)
				}
			}
		}
	}

	// Select crypto backend - use stored one if available, otherwise auto-select
	backendName := selectBackendForNode(node, forcedCrypto)
	backend, err := crypto.GetBackend(backendName)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto backend %s: %v", backendName, err)
	}

	log.Printf("KDC: Using %s backend for node %s", backendName, nodeID)

	// Parse node's public key using the selected backend
	// For JOSE, we use LongTermJosePubKey; for HPKE, we use LongTermPubKey
	var nodePubKey crypto.PublicKey
	if backendName == "hpke" {
		// Defensive check: refuse HPKE operations for JOSE-only nodes
		if len(node.SupportedCrypto) == 1 && node.SupportedCrypto[0] == "jose" {
			return nil, fmt.Errorf("node %s only supports JOSE crypto backend, cannot use HPKE", nodeID)
		}
		if node.LongTermHpkePubKey == nil || len(node.LongTermHpkePubKey) != 32 {
			return nil, fmt.Errorf("node %s has invalid HPKE public key length: %d (expected 32)", nodeID, len(node.LongTermHpkePubKey))
		}
		nodePubKey, err = backend.ParsePublicKey(node.LongTermHpkePubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node HPKE public key: %v", err)
		}
	} else if backendName == "jose" {
		if len(node.LongTermJosePubKey) == 0 {
			return nil, fmt.Errorf("node %s does not have a JOSE public key stored (required for JOSE backend)", nodeID)
		}
		nodePubKey, err = backend.ParsePublicKey(node.LongTermJosePubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node JOSE public key: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported crypto backend: %s", backendName)
	}

	// Filter to records for this node (or all nodes if nodeID is empty)
	// Normalize node IDs for comparison (handle trailing dot differences)
	nodeIDNormalized := strings.TrimSuffix(nodeID, ".")
	var nodeRecords []*DistributionRecord
	for _, record := range records {
		recordNodeIDNormalized := strings.TrimSuffix(record.NodeID, ".")
		if recordNodeIDNormalized == nodeIDNormalized || record.NodeID == "" {
			nodeRecords = append(nodeRecords, record)
		}
	}

	if len(nodeRecords) == 0 {
		log.Printf("KDC: Distribution %s exists but has no records for node %s (found %d records for other nodes)", distributionID, nodeID, len(records))
		return nil, fmt.Errorf("no distribution records found for node %s, distribution %s (distribution exists but not for this node)", nodeID, distributionID)
	}

	// Determine content type by analyzing all operations in this distribution
	contentType := determineContentType(nodeRecords)
	log.Printf("KDC: Distribution %s -> contentType=%s", distributionID, contentType)

	// Load KDC's signing key for JWS(JWE) authenticated distributions
	var kdcSigningKey crypto.PrivateKey
	if backendName == "jose" {
		// For JOSE, we can reuse the same P-256 key for both encryption and signing
		joseKeys, err := GetKdcJoseKeypair(conf.KdcJosePrivKey)
		if err != nil {
			log.Printf("KDC: Warning: Failed to load KDC JOSE signing key: %v (using unsigned distributions)", err)
			kdcSigningKey = nil
		} else {
			kdcSigningKey = joseKeys.PrivateKey
			log.Printf("KDC: Loaded KDC JOSE signing key for authenticated distributions")
		}
	} else if backendName == "hpke" {
		// For HPKE, we need a separate P-256 ECDSA signing key (X25519 can't sign)
		hpkeSigningKeys, err := GetKdcHpkeSigningKeypair(conf.KdcHpkeSigningKey)
		if err != nil {
			log.Printf("KDC: Warning: Failed to load KDC HPKE signing key: %v (using unsigned distributions)", err)
			kdcSigningKey = nil
		} else {
			kdcSigningKey = hpkeSigningKeys.PrivateKey
			log.Printf("KDC: Loaded KDC HPKE signing key for authenticated distributions")
		}
	}

	// Prepare encryption metadata for JWE protected headers
	encryptMetadata := make(map[string]interface{})
	encryptMetadata["distribution_id"] = distributionID
	encryptMetadata["timestamp"] = time.Now().Format(time.RFC3339)
	encryptMetadata["sender"] = "kdc"
	encryptMetadata["content_type"] = contentType

	var base64Data []byte
	var zoneCount int
	var keyCount int
	var operationCount int

	if contentType == "node_operations" {
		var err error
		base64Data, zoneCount, keyCount, err = kdc.buildNodeOperationsPayload(
			nodeRecords, distributionID, backend, backendName, kdcSigningKey)
		if err != nil {
			return nil, err
		}
		operationCount = 0
	} else if contentType == "key_operations" || contentType == "mgmt_operations" || contentType == "mixed_operations" {
		var err error
		base64Data, zoneCount, keyCount, operationCount, err = kdc.buildKeyOperationsPayload(
			nodeRecords, distributionID, nodeID, backend, backendName, nodePubKey, kdcSigningKey, encryptMetadata)
		if err != nil {
			return nil, err
		}
		log.Printf("KDC: Prepared %s: %d operations (%d key ops) for %d zones",
			contentType, operationCount, keyCount, zoneCount)
	} else {
		return nil, fmt.Errorf("invalid or unsupported content type: %s for distribution %s", contentType, distributionID)
	}

	// Calculate checksum
	hash := sha256.Sum256([]byte(base64Data))
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Get component count for node_operations if needed
	componentCount := 0
	if contentType == "node_operations" {
		_, intendedComponents, err := kdc.GetDistributionComponentList(distributionID)
		if err == nil {
			componentCount = len(intendedComponents)
			log.Printf("KDC: Set component_count in metadata to %d (from stored distribution component list)", componentCount)
		} else {
			log.Printf("KDC: Warning: Failed to get component list for distribution %s to set metadata: %v", distributionID, err)
		}
	}

	// Create manifest metadata (used for JSON format)
	metadata := buildManifestMetadata(
		contentType, distributionID, nodeID, backendName,
		zoneCount, keyCount, operationCount, componentCount, conf)

	// Determine if JWT format will be used (signing key available)
	// and create a template for size estimation if so
	var jwtClaimsTemplate *nmdistrib.JWTManifestClaims
	if kdcSigningKey != nil {
		jwtClaimsTemplate = &nmdistrib.JWTManifestClaims{
			Issuer:         "kdc",
			Subject:        "distribution",
			IssuedAt:       time.Now().Unix(),
			DistributionID: distributionID,
			ReceiverID:     nodeID,
			Content:        contentType,
			Crypto:         backendName,
			ChunkHash:      checksum,
			ZoneCount:      zoneCount,
			KeyCount:       keyCount,
			OperationCount: operationCount,
		}
		// Add TTL fields for estimation
		if conf != nil && conf.RetireTime > 0 {
			jwtClaimsTemplate.RetireTime = conf.RetireTime.String()
		}
		if conf != nil && conf.GetDistributionTTL() > 0 {
			jwtClaimsTemplate.DistributionTTL = conf.GetDistributionTTL().String()
		}
	}

	// Split into chunks (or include inline)
	// Pass JWT claims template if JWT format will be used, for accurate size estimation
	chunkCount, chunkSize, dataChunks, err := splitIntoChunks(base64Data, metadata, jwtClaimsTemplate, conf)
	if err != nil {
		return nil, err
	}

	// Create manifest CHUNK
	// Use JWT format when signing key is available (provides signature instead of HMAC)
	// Otherwise fall back to JSON format with HMAC
	var manifestCHUNK *core.CHUNK

	if kdcSigningKey != nil {
		// Use JWT format with flattened claims and built-in signature
		// Start from the template and add chunk info (TTLs already set in template)
		claims := jwtClaimsTemplate
		claims.ChunkCount = chunkCount
		claims.ChunkSize = chunkSize

		// Include payload inline if chunkCount is 0
		if chunkCount == 0 {
			claims.Payload = base64.StdEncoding.EncodeToString(base64Data)
		}

		manifestCHUNK, err = nmdistrib.CreateJWTManifest(claims, kdcSigningKey, backend)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT manifest: %v", err)
		}
		log.Printf("KDC: Created JWT manifest with signature for node %s (format=JWT)", nodeID)
	} else {
		// Fall back to JSON format with HMAC
		manifestData := &distrib.ManifestData{
			ChunkCount: chunkCount,
			ChunkSize:  chunkSize,
			Metadata:   metadata,
		}

		// Include payload inline if chunkCount is 0 (indicates inline payload)
		if chunkCount == 0 {
			manifestData.Payload = make([]byte, len(base64Data))
			copy(manifestData.Payload, base64Data)
		}

		// Create manifest CHUNK (Sequence=0, Total=chunkCount)
		manifestCHUNK, err = distrib.CreateCHUNKManifest(manifestData, core.FormatJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to create CHUNK manifest: %v", err)
		}

		// Calculate HMAC using the recipient node's long-term public key
		// Select the appropriate key based on the crypto backend used for encryption
		var hmacKey []byte
		if backendName == "hpke" {
			// For HPKE, use the X25519 public key directly (32 bytes)
			if node.LongTermHpkePubKey == nil || len(node.LongTermHpkePubKey) != 32 {
				return nil, fmt.Errorf("node %s has invalid HPKE public key for HMAC: length %d (expected 32)", nodeID, len(node.LongTermHpkePubKey))
			}
			hmacKey = node.LongTermHpkePubKey
		} else if backendName == "jose" {
			// For JOSE, extract the x-coordinate from the ECDSA P-256 public key (32 bytes)
			if len(node.LongTermJosePubKey) == 0 {
				return nil, fmt.Errorf("node %s does not have a JOSE public key stored (required for HMAC)", nodeID)
			}
			// Parse JWK to extract ECDSA public key
			var jwk jose.JSONWebKey
			if err := json.Unmarshal(node.LongTermJosePubKey, &jwk); err != nil {
				return nil, fmt.Errorf("failed to parse node JOSE public key for HMAC: %v", err)
			}
			ecdsaKey, ok := jwk.Key.(*ecdsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("node %s JOSE public key is not an ECDSA key (required for HMAC)", nodeID)
			}
			// Validate curve is P-256 (required for this backend)
			if ecdsaKey.Curve != elliptic.P256() {
				return nil, fmt.Errorf("node %s JOSE public key uses unsupported curve: %s (expected P-256)", nodeID, ecdsaKey.Curve.Params().Name)
			}
			// Extract x-coordinate (32 bytes for P-256)
			xBytes := ecdsaKey.X.Bytes()
			// Calculate expected coordinate length for P-256: (256 bits + 7) / 8 = 32 bytes
			expectedLen := (ecdsaKey.Curve.Params().BitSize + 7) / 8
			if len(xBytes) > expectedLen {
				return nil, fmt.Errorf("node %s JOSE public key x-coordinate too large: %d bytes (max: %d for P-256)", nodeID, len(xBytes), expectedLen)
			}
			// Pad to expectedLen bytes if needed (ECDSA coordinates are variable length)
			hmacKey = make([]byte, expectedLen)
			copy(hmacKey[expectedLen-len(xBytes):], xBytes)
		} else {
			return nil, fmt.Errorf("unsupported crypto backend for HMAC: %s", backendName)
		}
		if err := distrib.CalculateCHUNKHMAC(manifestCHUNK, hmacKey); err != nil {
			return nil, fmt.Errorf("failed to calculate HMAC: %v", err)
		}
		log.Printf("KDC: Created JSON manifest with HMAC for node %s (format=JSON)", nodeID)
	}

	// Create CHUNK records (manifest + data chunks)
	allChunks := make([]*core.CHUNK, 0)
	allChunks = append(allChunks, manifestCHUNK)
	if chunkCount > 0 {
		if dataChunks == nil || len(dataChunks) == 0 {
			return nil, fmt.Errorf("expected %d data chunks but got %d", chunkCount, len(dataChunks))
		}
		if len(dataChunks) != int(chunkCount) {
			return nil, fmt.Errorf("chunk count mismatch: expected %d data chunks but got %d", chunkCount, len(dataChunks))
		}
		// Validate chunk sequence numbers before appending
		for i, chunk := range dataChunks {
			if chunk.Sequence == 0 || chunk.Total == 0 {
				return nil, fmt.Errorf("invalid chunk at index %d: sequence=%d, total=%d (expected sequence=%d, total=%d)",
					i, chunk.Sequence, chunk.Total, i+1, chunkCount)
			}
			if chunk.Sequence != uint16(i+1) {
				return nil, fmt.Errorf("chunk sequence mismatch at index %d: got sequence=%d, expected %d",
					i, chunk.Sequence, i+1)
			}
			if chunk.Total != chunkCount {
				return nil, fmt.Errorf("chunk total mismatch at index %d: got total=%d, expected %d",
					i, chunk.Total, chunkCount)
			}
		}
		allChunks = append(allChunks, dataChunks...)
		log.Printf("KDC: Assembled %d chunks: manifest (index 0) + %d data chunks (indices 1-%d)",
			len(allChunks), len(dataChunks), len(allChunks)-1)
	}

	prepared := &preparedChunks{
		chunks:    allChunks,
		checksum:  checksum,
		timestamp: 0,
	}

	// Cache it
	globalChunkCache.mu.Lock()
	globalChunkCache.cache[cacheKey] = prepared
	globalChunkCache.mu.Unlock()

	log.Printf("KDC: Prepared %d CHUNK records for node %s, distribution %s using %s backend",
		len(allChunks), nodeID, distributionID, backendName)
	return prepared, nil
}
