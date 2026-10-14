/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Chunk preparation and retrieval for CHUNK queries
 */

package kdc

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/distrib"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"

	tnm "github.com/johanix/tdns-nm/tnm"
)

// chunkCache stores prepared chunks in memory (keyed by nodeID+distributionID)
type chunkCache struct {
	mu    sync.RWMutex
	cache map[string]*preparedChunks
}

type preparedChunks struct {
	chunks    []*core.CHUNK // CHUNK records (manifest + data chunks)
	checksum  string
	timestamp int64
}

var globalChunkCache = &chunkCache{
	cache: make(map[string]*preparedChunks),
}

// validateHPKEForNode validates that a node can use HPKE operations
// Checks that the node is not JOSE-only and has a valid HPKE public key
func validateHPKEForNode(node *Node, nodeID, purpose string) error {
	if len(node.SupportedCrypto) == 1 && node.SupportedCrypto[0] == "jose" {
		return fmt.Errorf("node %s only supports JOSE crypto backend, cannot use HPKE for %s", nodeID, purpose)
	}
	if node.LongTermHpkePubKey == nil || len(node.LongTermHpkePubKey) != 32 {
		return fmt.Errorf("node %s has invalid public key for %s: length %d (expected 32)", nodeID, purpose, len(node.LongTermHpkePubKey))
	}
	return nil
}

// prepareChunksForNodeV1 prepares chunks for a node's distribution event (V1 implementation using HPKE)
// This is called on-demand when CHUNK is queried
func (kdc *KdcDB) prepareChunksForNodeV1(nodeID, distributionID string, conf *tnm.KdcConf) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached chunks for node %s, distribution %s", nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing chunks for node %s, distribution %s", nodeID, distributionID)

	// Get the node to access its long-term public key for HMAC
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
	}
	// Validate HPKE eligibility once at the start (covers HMAC and encryption operations)
	if err := validateHPKEForNode(node, nodeID, "HPKE operations"); err != nil {
		return nil, err
	}

	// Get all distribution records for this distributionID
	records, err := kdc.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get distribution records: %v", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no distribution records found for distribution %s (may have been purged after completion)", distributionID)
	}

	// Filter to records for this node (or all nodes if nodeID is empty)
	var nodeRecords []*DistributionRecord
	for _, record := range records {
		if record.NodeID == nodeID || record.NodeID == "" {
			nodeRecords = append(nodeRecords, record)
		}
	}

	if len(nodeRecords) == 0 {
		log.Printf("KDC: Distribution %s exists but has no records for node %s (found %d records for other nodes)", distributionID, nodeID, len(records))
		return nil, fmt.Errorf("no distribution records found for node %s, distribution %s (distribution exists but not for this node)", nodeID, distributionID)
	}

	// Determine content type by analyzing all operations in this distribution
	// Categorize operations into domains and check for conflicts
	hasNodeOps := false // update_components
	hasKeyOps := false  // roll_key, delete_key
	hasMgmtOps := false // ping

	for _, record := range nodeRecords {
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

	log.Printf("KDC: Distribution %s contains: node_ops=%v, key_ops=%v, mgmt_ops=%v -> contentType=%s",
		distributionID, hasNodeOps, hasKeyOps, hasMgmtOps, contentType)

	var base64Data []byte
	var zoneCount int
	var keyCount int
	var operationCount int

	if contentType == "node_operations" {
		// For node_operations (update_components) distributions, use the encrypted data directly from the distribution record
		// The distribution record already contains the correct encrypted component list
		// (created with the intended component list, not the current DB state)
		if len(nodeRecords) != 1 {
			return nil, fmt.Errorf("node_operations distribution should have exactly one record, got %d", len(nodeRecords))
		}

		record := nodeRecords[0]
		if record.Operation != "update_components" {
			return nil, fmt.Errorf("node_operations distribution has non-update_components operation: %s", record.Operation)
		}

		// The distribution record already contains the encrypted component list
		// Format stored: <ephemeral_pub_key (32 bytes)><ciphertext>
		// We just need to combine them and base64 encode
		if len(record.EphemeralPubKey) != 32 {
			return nil, fmt.Errorf("invalid ephemeral public key length: %d (expected 32)", len(record.EphemeralPubKey))
		}

		// Combine ephemeral public key and ciphertext for transport
		// Format: <ephemeral_pub_key (32 bytes)><ciphertext>
		encryptedData := append(record.EphemeralPubKey, record.EncryptedKey...)

		// Base64 encode the encrypted data
		base64Data = []byte(base64.StdEncoding.EncodeToString(encryptedData))

		log.Printf("KDC: Using encrypted component list from distribution record: encrypted %d bytes -> base64 %d bytes",
			len(encryptedData), len(base64Data))

		zoneCount = 0 // node_operations doesn't have zones
		keyCount = 0  // node_operations doesn't have keys
	} else if contentType == "key_operations" || contentType == "mgmt_operations" || contentType == "mixed_operations" {
		// Prepare JSON structure with operation-based distribution entries
		// Supports key operations (roll_key, delete_key), management operations (ping), or mixed
		// The entire JSON will be encrypted using HPKE
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
				// Ping operation (management) - metadata already contains nonce and timestamp
				// No additional fields needed

			case string(OperationDeleteKey):
				// Delete key operation - populate zone_name and key_id
				entry.ZoneName = record.ZoneName
				entry.KeyID = record.KeyID

				zoneSet[record.ZoneName] = true

			default:
				log.Printf("KDC: Warning: Unknown operation type %q in distribution %s", record.Operation, distributionID)
				continue
			}

			entries = append(entries, entry)
		}

		operationCount = len(entries)
		keyCount = 0 // For key_operations, count the actual key operations
		for _, entry := range entries {
			if entry.Operation == "roll_key" || entry.Operation == "delete_key" {
				keyCount++
			}
		}
		zoneCount = len(zoneSet)

		if operationCount == 0 {
			return nil, fmt.Errorf("no valid operations found for node %s, distribution %s", nodeID, distributionID)
		}

		// Marshal to JSON (cleartext)
		entriesJSON, err := json.Marshal(entries)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal entries JSON: %v", err)
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

		log.Printf("KDC: Prepared %s: %d operations (%d key ops) for %d zones, JSON size: %d bytes",
			contentType, operationCount, keyCount, zoneCount, len(entriesJSON))

		// Encrypt the entire JSON payload using HPKE and encode for transport
		base64Data, err = tnm.EncryptAndEncode(node.LongTermHpkePubKey, entriesJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt distribution payload: %v", err)
		}
		log.Printf("KDC: Encrypted distribution payload: cleartext %d bytes -> base64 %d bytes",
			len(entriesJSON), len(base64Data))
	} else {
		// Should never reach here - all valid content types should be handled above
		return nil, fmt.Errorf("invalid or unsupported content type: %s for distribution %s", contentType, distributionID)
	}

	// Calculate checksum
	hash := sha256.Sum256([]byte(base64Data))
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Create manifest metadata
	extraFields := make(map[string]interface{})
	if contentType == "key_operations" || contentType == "mgmt_operations" || contentType == "mixed_operations" {
		// For operation-based distributions, include operation counts
		extraFields["zone_count"] = zoneCount
		extraFields["key_count"] = keyCount
		extraFields["operation_count"] = operationCount
	} else if contentType == "node_operations" {
		// For node_operations (update_components), get component count from the stored component list
		// This ensures the metadata matches the actual payload (which comes from the distribution record)
		_, intendedComponents, err := kdc.GetDistributionComponentList(distributionID)
		if err == nil {
			extraFields["component_count"] = len(intendedComponents)
			log.Printf("KDC: Set component_count in metadata to %d (from stored distribution component list)", len(intendedComponents))
		} else {
			// Fallback: if we can't get the stored list, log a warning but don't fail
			log.Printf("KDC: Warning: Failed to get component list for distribution %s to set metadata: %v", distributionID, err)
			// Don't set component_count if we can't get the correct value
		}
	}
	// Add retire_time from config if available
	if conf != nil && conf.RetireTime > 0 {
		extraFields["retire_time"] = conf.RetireTime.String() // Convert duration to string (e.g., "168h0m0s")
	}
	// Add distribution_ttl from config if available (for KRS validation)
	if conf != nil && conf.GetDistributionTTL() > 0 {
		extraFields["distribution_ttl"] = conf.GetDistributionTTL().String() // Convert duration to string (e.g., "5m0s")
	}
	metadata := tnm.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)

	// Determine if payload should be included inline
	payloadSize := len(base64Data)
	testSize := distrib.EstimateManifestSize(metadata, base64Data)

	// Check if the manifest fits in DNS message (accounting for headers and QNAME)
	// Estimate: DNS headers (~12) + QNAME (~100) + RR header (~10) + manifest data
	const estimatedDNSOverhead = 150
	estimatedTotalSize := estimatedDNSOverhead + testSize
	includeInline := distrib.ShouldIncludePayloadInline(payloadSize, estimatedTotalSize)

	var dataChunks []*core.CHUNK
	var chunkCount uint16
	var chunkSize uint16

	if includeInline {
		// Payload fits inline, include it directly in manifest
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - including inline in CHUNK manifest",
			payloadSize, testSize, estimatedTotalSize)
	} else {
		// Payload is too large, split into chunks
		chunkSizeInt := conf.GetChunkMaxSize()
		dataChunks = distrib.SplitIntoCHUNKs([]byte(base64Data), chunkSizeInt, core.FormatJSON)
		// Check if SplitIntoCHUNKs returned nil (indicates overflow)
		if dataChunks == nil && len(base64Data) > 0 {
			return nil, fmt.Errorf("failed to split payload into chunks: overflow detected (payload size: %d bytes, chunk size: %d bytes)", len(base64Data), chunkSizeInt)
		}
		// Check for integer overflow before converting to uint16
		if len(dataChunks) > math.MaxUint16 {
			return nil, fmt.Errorf("too many chunks: %d (max: %d)", len(dataChunks), math.MaxUint16)
		}
		if chunkSizeInt > math.MaxUint16 {
			return nil, fmt.Errorf("chunk size too large: %d (max: %d)", chunkSizeInt, math.MaxUint16)
		}
		chunkCount = uint16(len(dataChunks))
		chunkSize = uint16(chunkSizeInt)
		log.Printf("KDC: Payload size %d bytes (base64), manifest size %d bytes, estimated total %d bytes - exceeds inline threshold, splitting into %d chunks",
			payloadSize, testSize, estimatedTotalSize, chunkCount)
	}

	// Create manifest data
	manifestData := &distrib.ManifestData{
		ChunkCount: chunkCount,
		ChunkSize:  chunkSize,
		Metadata:   metadata,
	}

	// Include payload inline if it fits
	if includeInline {
		manifestData.Payload = make([]byte, len(base64Data))
		copy(manifestData.Payload, base64Data)
	}

	// Create manifest CHUNK (Sequence=0, Total=chunkCount)
	manifestCHUNK, err := distrib.CreateCHUNKManifest(manifestData, core.FormatJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create CHUNK manifest: %v", err)
	}

	// Calculate HMAC using the recipient node's long-term public key
	// This ensures each distribution is authenticated for the specific recipient node
	if err := distrib.CalculateCHUNKHMAC(manifestCHUNK, node.LongTermHpkePubKey); err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC: %v", err)
	}
	log.Printf("KDC: Calculated HMAC for CHUNK manifest using node %s public key (%d bytes)", nodeID, len(manifestCHUNK.HMAC))

	// Create CHUNK records (manifest + data chunks)
	allChunks := make([]*core.CHUNK, 0)
	allChunks = append(allChunks, manifestCHUNK)
	allChunks = append(allChunks, dataChunks...)

	prepared := &preparedChunks{
		chunks:    allChunks,
		checksum:  checksum,
		timestamp: 0, // TODO: add timestamp
	}

	// Cache it
	globalChunkCache.mu.Lock()
	globalChunkCache.cache[cacheKey] = prepared
	globalChunkCache.mu.Unlock()

	log.Printf("KDC: Prepared %d CHUNK records for node %s, distribution %s",
		len(allChunks), nodeID, distributionID)
	return prepared, nil
}

// GetCHUNKForNode retrieves a CHUNK record for a node's distribution event
// chunkID 0 returns the manifest CHUNK (Sequence=0), chunkID > 0 returns data CHUNK (Sequence>0)
func (kdc *KdcDB) GetCHUNKForNode(nodeID, distributionID string, chunkID uint16, conf *tnm.KdcConf) (*core.CHUNK, error) {
	prepared, err := kdc.prepareChunksForNode(nodeID, distributionID, conf)
	if err != nil {
		return nil, err
	}

	if int(chunkID) >= len(prepared.chunks) {
		return nil, fmt.Errorf("CHUNK ID %d out of range (max %d)", chunkID, len(prepared.chunks)-1)
	}

	chunk := prepared.chunks[chunkID]
	// Debug: Check if Data field is JSON or base64
	dataPreview := ""
	if len(chunk.Data) > 0 {
		if chunk.Data[0] == '{' || chunk.Data[0] == '[' {
			dataPreview = "JSON"
			if len(chunk.Data) > 50 {
				dataPreview += fmt.Sprintf(" (starts with: %q...)", string(chunk.Data[:50]))
			} else {
				dataPreview += fmt.Sprintf(" (content: %q)", string(chunk.Data))
			}
		} else {
			dataPreview = "base64"
			if len(chunk.Data) > 20 {
				dataPreview += fmt.Sprintf(" (starts with: %q...)", string(chunk.Data[:20]))
			} else {
				dataPreview += fmt.Sprintf(" (content: %q)", string(chunk.Data))
			}
		}
	}
	log.Printf("KDC: GetCHUNKForNode: returning chunkID=%d (array index %d): sequence=%d, total=%d, data_len=%d, data_type=%s",
		chunkID, chunkID, chunk.Sequence, chunk.Total, len(chunk.Data), dataPreview)
	return chunk, nil
}

// GetDistributionRecordsForDistributionID gets all distribution records for a distribution ID
func (kdc *KdcDB) GetDistributionRecordsForDistributionID(distributionID string) ([]*DistributionRecord, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key,
			created_at, expires_at, status, distribution_id, completed_at, operation, payload
			FROM distribution_records
			WHERE distribution_id = ?
			ORDER BY created_at DESC`,
		distributionID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution records: %v", err)
	}
	defer rows.Close()

	var records []*DistributionRecord
	for rows.Next() {
		record := &DistributionRecord{}
		var zoneName sql.NullString
		var keyID sql.NullString
		var nodeID sql.NullString
		var expiresAt sql.NullTime
		var completedAt sql.NullTime
		var statusStr string
		var operationStr sql.NullString
		var payloadJSON sql.NullString
		if err := rows.Scan(
			&record.ID, &zoneName, &keyID, &nodeID,
			&record.EncryptedKey, &record.EphemeralPubKey, &record.CreatedAt,
			&expiresAt, &statusStr, &record.DistributionID, &completedAt,
			&operationStr, &payloadJSON,
		); err != nil {
			return nil, fmt.Errorf("failed to scan distribution record: %v", err)
		}
		if zoneName.Valid {
			record.ZoneName = zoneName.String
		}
		if keyID.Valid {
			record.KeyID = keyID.String
		}
		if nodeID.Valid {
			record.NodeID = nodeID.String
		}
		if expiresAt.Valid {
			record.ExpiresAt = &expiresAt.Time
		}
		if completedAt.Valid {
			record.CompletedAt = &completedAt.Time
		}
		if operationStr.Valid {
			record.Operation = operationStr.String
		}
		if payloadJSON.Valid && payloadJSON.String != "" {
			var payload map[string]interface{}
			if err := json.Unmarshal([]byte(payloadJSON.String), &payload); err != nil {
				log.Printf("KDC: Warning: Failed to unmarshal payload for record %s: %v", record.ID, err)
				// Continue without payload rather than failing
			} else {
				record.Payload = payload
			}
		}
		record.Status = DistributionStatus(statusStr)
		records = append(records, record)
	}
	return records, rows.Err()
}

// DistributionInfo contains distribution ID and the nodes it applies to
type DistributionInfo struct {
	DistributionID string   `json:"distribution_id"`
	Nodes          []string `json:"nodes"`
}

// GetAllDistributionIDs returns all unique distribution IDs from distribution_records and cache
func (kdc *KdcDB) GetAllDistributionIDs() ([]string, error) {
	infos, err := kdc.GetAllDistributionInfos()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(infos))
	for i, info := range infos {
		ids[i] = info.DistributionID
	}
	return ids, nil
}

// GetAllDistributionInfos returns all distribution IDs with their associated nodes
func (kdc *KdcDB) GetAllDistributionInfos() ([]DistributionInfo, error) {
	// Get distribution IDs and nodes from database
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT distribution_id, node_id FROM distribution_records ORDER BY distribution_id, node_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution IDs: %v", err)
	}
	defer rows.Close()

	distributionMap := make(map[string]map[string]bool) // distID -> set of nodeIDs
	for rows.Next() {
		var distID string
		var nodeID sql.NullString
		if err := rows.Scan(&distID, &nodeID); err != nil {
			return nil, fmt.Errorf("failed to scan distribution ID: %v", err)
		}
		if distributionMap[distID] == nil {
			distributionMap[distID] = make(map[string]bool)
		}
		if nodeID.Valid && nodeID.String != "" {
			distributionMap[distID][nodeID.String] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Also get distribution IDs from cache (for test distributions)
	globalChunkCache.mu.RLock()
	for cacheKey := range globalChunkCache.cache {
		// Cache key format: "nodeID:distributionID"
		parts := strings.Split(cacheKey, ":")
		if len(parts) == 2 {
			nodeID := parts[0]
			distID := parts[1]
			// Skip if distribution ID is empty
			if distID == "" {
				log.Printf("KDC: Warning: found cache entry with empty distribution ID: %s", cacheKey)
				continue
			}
			if distributionMap[distID] == nil {
				distributionMap[distID] = make(map[string]bool)
			}
			distributionMap[distID][nodeID] = true
		} else {
			log.Printf("KDC: Warning: invalid cache key format (expected 'nodeID:distributionID'): %s", cacheKey)
		}
	}
	globalChunkCache.mu.RUnlock()

	// Convert map to sorted slice
	distributionIDs := make([]string, 0, len(distributionMap))
	for distID := range distributionMap {
		distributionIDs = append(distributionIDs, distID)
	}
	sort.Strings(distributionIDs)

	infos := make([]DistributionInfo, 0, len(distributionIDs))
	for _, distID := range distributionIDs {
		// Skip empty distribution IDs
		if distID == "" {
			log.Printf("KDC: Warning: skipping empty distribution ID")
			continue
		}
		nodeSet := distributionMap[distID]
		nodes := make([]string, 0, len(nodeSet))
		for nodeID := range nodeSet {
			nodes = append(nodes, nodeID)
		}
		sort.Strings(nodes)
		infos = append(infos, DistributionInfo{
			DistributionID: distID,
			Nodes:          nodes,
		})
	}
	return infos, nil
}

// DeleteDistribution deletes all distribution records for a given distribution ID
func (kdc *KdcDB) DeleteDistribution(distributionID string) error {
	_, err := kdc.DB.Exec(
		`DELETE FROM distribution_records WHERE distribution_id = ?`,
		distributionID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete distribution records: %v", err)
	}
	return nil
}

// ClearDistributionCache clears the chunk cache for a distribution
func ClearDistributionCache(distributionID string) {
	globalChunkCache.mu.Lock()
	defer globalChunkCache.mu.Unlock()

	// Remove all cache entries matching this distribution ID
	for key := range globalChunkCache.cache {
		if strings.HasSuffix(key, ":"+distributionID) {
			delete(globalChunkCache.cache, key)
		}
	}
}

// PrepareTextChunks prepares chunks for a text distribution (clear_text or encrypted_text)
// This creates a persistent distribution record that can be queried by KRS
// contentType should be "clear_text" or "encrypted_text"
func (kdc *KdcDB) PrepareTextChunks(nodeID, distributionID, text string, contentType string, conf *tnm.KdcConf) (*preparedChunks, error) {
	cacheKey := fmt.Sprintf("%s:%s", nodeID, distributionID)

	// Check cache first
	globalChunkCache.mu.RLock()
	if cached, ok := globalChunkCache.cache[cacheKey]; ok {
		globalChunkCache.mu.RUnlock()
		log.Printf("KDC: Using cached %s chunks for node %s, distribution %s", contentType, nodeID, distributionID)
		return cached, nil
	}
	globalChunkCache.mu.RUnlock()

	// Not in cache, prepare chunks
	log.Printf("KDC: Preparing %s chunks for node %s, distribution %s", contentType, nodeID, distributionID)

	// Get the node to access its long-term public key for HMAC
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
	}
	// Validate HPKE eligibility once at the start (covers encryption and HMAC operations)
	if err := validateHPKEForNode(node, nodeID, "HPKE operations"); err != nil {
		return nil, err
	}

	var dataToChunk []byte
	// var err error

	if contentType == "encrypted_text" {
		// Encrypt the text using HPKE and encode for transport
		dataToChunk, err = tnm.EncryptAndEncode(node.LongTermHpkePubKey, []byte(text))
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt text: %v", err)
		}
		log.Printf("KDC: Encrypted text (%d bytes) -> base64 (%d bytes)", len(text), len(dataToChunk))
	} else {
		// clear_text: just base64 encode the text
		dataToChunk = []byte(base64.StdEncoding.EncodeToString([]byte(text)))
	}

	// Calculate checksum
	hash := sha256.Sum256(dataToChunk)
	checksum := fmt.Sprintf("sha256:%x", hash)

	// Determine if payload should be included inline
	payloadSize := len(dataToChunk)
	testMetadata := map[string]interface{}{
		"content":         contentType,
		"distribution_id": distributionID,
		"node_id":         nodeID,
		"text_length":     len(text),
	}
	testSize := distrib.EstimateManifestSize(testMetadata, dataToChunk)

	// Check if the manifest fits in DNS message
	const estimatedDNSOverhead = 150
	estimatedTotalSize := estimatedDNSOverhead + testSize
	includeInline := distrib.ShouldIncludePayloadInline(payloadSize, estimatedTotalSize)

	var dataChunks []*core.CHUNK
	var chunkCount uint16
	var chunkSize uint16

	if includeInline {
		// Payload fits inline, include it directly in manifest
		chunkCount = 0
		chunkSize = 0
		log.Printf("KDC: Test text payload size %d bytes, manifest size %d bytes, estimated total %d bytes - including inline in CHUNK manifest",
			payloadSize, testSize, estimatedTotalSize)
	} else {
		// Payload is too large, split into chunks
		chunkSizeInt := conf.GetChunkMaxSize()
		dataChunks = distrib.SplitIntoCHUNKs(dataToChunk, chunkSizeInt, core.FormatJSON)
		// Check if SplitIntoCHUNKs returned nil (indicates overflow)
		if dataChunks == nil && len(dataToChunk) > 0 {
			return nil, fmt.Errorf("failed to split payload into chunks: overflow detected (payload size: %d bytes, chunk size: %d bytes)", len(dataToChunk), chunkSizeInt)
		}
		// Check for integer overflow before converting to uint16
		if len(dataChunks) > math.MaxUint16 {
			return nil, fmt.Errorf("too many chunks: %d (max: %d)", len(dataChunks), math.MaxUint16)
		}
		if chunkSizeInt > math.MaxUint16 {
			return nil, fmt.Errorf("chunk size too large: %d (max: %d)", chunkSizeInt, math.MaxUint16)
		}
		chunkCount = uint16(len(dataChunks))
		chunkSize = uint16(chunkSizeInt)
		log.Printf("KDC: Test text payload size %d bytes, manifest size %d bytes, estimated total %d bytes - exceeds inline threshold, splitting into %d chunks",
			payloadSize, testSize, estimatedTotalSize, chunkCount)
	}

	// Create manifest data
	extraFields := map[string]interface{}{
		"text_length": len(text),
	}
	metadata := tnm.CreateManifestMetadata(contentType, distributionID, nodeID, extraFields)
	manifestData := &distrib.ManifestData{
		ChunkCount: chunkCount,
		ChunkSize:  chunkSize,
		Metadata:   metadata,
	}

	// Include payload inline if it fits
	if includeInline {
		manifestData.Payload = make([]byte, len(dataToChunk))
		copy(manifestData.Payload, dataToChunk)
	}

	// Create manifest CHUNK (Sequence=0, Total=chunkCount)
	manifestCHUNK, err := distrib.CreateCHUNKManifest(manifestData, core.FormatJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create CHUNK manifest: %v", err)
	}

	// Calculate HMAC using the recipient node's long-term public key
	// This ensures each distribution is authenticated for the specific recipient node
	// (HPKE eligibility already validated at function start)
	if err := distrib.CalculateCHUNKHMAC(manifestCHUNK, node.LongTermHpkePubKey); err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC: %v", err)
	}
	log.Printf("KDC: Calculated HMAC for CHUNK manifest using node %s public key (%d bytes)", nodeID, len(manifestCHUNK.HMAC))

	// Create CHUNK records (manifest + data chunks)
	allChunks := make([]*core.CHUNK, 0)
	allChunks = append(allChunks, manifestCHUNK)
	allChunks = append(allChunks, dataChunks...)

	prepared := &preparedChunks{
		chunks:    allChunks,
		checksum:  checksum,
		timestamp: 0,
	}

	// Cache it
	globalChunkCache.mu.Lock()
	globalChunkCache.cache[cacheKey] = prepared
	globalChunkCache.mu.Unlock()

	// Create a dummy distribution record in the database so it shows up in listings
	// Use special placeholder values for test distributions
	distRecordID := make([]byte, 16)
	if _, err := rand.Read(distRecordID); err != nil {
		log.Printf("KDC: Warning: Failed to generate distribution record ID: %v", err)
	} else {
		distRecordIDHex := hex.EncodeToString(distRecordID)
		// Create a dummy distribution record with placeholder values
		// We use "test" as zone_id and key_id, but these don't need to exist due to
		// the way we query (we also check cache)
		distRecord := &DistributionRecord{
			ID:              distRecordIDHex,
			ZoneName:        "_test_distribution_", // Placeholder zone for test distributions
			KeyID:           "_test_key_",          // Placeholder key for test distributions
			NodeID:          nodeID,
			EncryptedKey:    []byte{}, // Empty for test distributions
			EphemeralPubKey: []byte{}, // Empty for test distributions
			CreatedAt:       time.Now(),
			ExpiresAt:       nil,
			Status:          DistributionStatusPending,
			DistributionID:  distributionID,
		}

		// Try to insert, but don't fail if it doesn't work (e.g., foreign key constraints)
		if err := kdc.AddDistributionRecord(distRecord); err != nil {
			log.Printf("KDC: Warning: Failed to store test distribution record in database (this is OK for test distributions): %v", err)
			// Continue anyway - the distribution is cached and will work
		}
	}

	log.Printf("KDC: Prepared %d %s chunks for node %s, distribution %s", len(allChunks), contentType, nodeID, distributionID)
	return prepared, nil
}

// PrepareTestTextChunks is a convenience wrapper for backward compatibility
// It calls PrepareTextChunks with contentType="clear_text"
func (kdc *KdcDB) PrepareTestTextChunks(nodeID, distributionID, testText string, conf *tnm.KdcConf) (*preparedChunks, error) {
	return kdc.PrepareTextChunks(nodeID, distributionID, testText, "clear_text", conf)
}
