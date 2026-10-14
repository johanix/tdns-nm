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

	nmdistrib "github.com/johanix/tdns-nm/tnm/distrib"
	"github.com/johanix/tdns-transport/v2/crypto"
	"github.com/johanix/tdns-transport/v2/distrib"
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

	// Get the node to access its long-term JOSE public key (encryption and HMAC)
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %v", nodeID, err)
	}
	hmacKey, err := nodeJoseHMACKey(node)
	if err != nil {
		return nil, err
	}

	var dataToChunk []byte

	if contentType == "encrypted_text" {
		// Encrypt the text to the node and sign it with the KDC key: JWS(JWE(text))
		backend, err := crypto.GetBackend("jose")
		if err != nil {
			return nil, fmt.Errorf("failed to get JOSE backend: %v", err)
		}
		nodePubKey, err := backend.ParsePublicKey(node.LongTermJosePubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node JOSE public key: %v", err)
		}
		joseKeys, err := GetKdcJoseKeypair(conf.KdcJosePrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load KDC JOSE signing key: %v", err)
		}
		dataToChunk, err = nmdistrib.EncryptSignAndEncode(backend, nodePubKey, []byte(text), joseKeys.PrivateKey, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt text: %v", err)
		}
		log.Printf("KDC: Encrypted and signed text (%d bytes) -> base64 (%d bytes)", len(text), len(dataToChunk))
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
	if err := distrib.CalculateCHUNKHMAC(manifestCHUNK, hmacKey); err != nil {
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
