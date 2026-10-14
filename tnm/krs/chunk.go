/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CHUNK query handling for tdns-krs
 * CHUNK query handling for tdns-krs
 */

package krs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	nmdistrib "github.com/johanix/tdns-nm/tnm/distrib"
	"github.com/johanix/tdns-transport/v2/crypto"
	"github.com/johanix/tdns-transport/v2/distrib"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"

	tnm "github.com/johanix/tdns-nm/tnm"
)

// QueryCHUNK queries the KDC for a CHUNK record
// sequence: 0 for manifest, 1+ for data chunks
// chunkSize is the expected chunk size from the manifest (0 if unknown, used for TCP decision)
func QueryCHUNK(krsDB *KrsDB, conf *tnm.KrsConf, nodeID, distributionID string, sequence uint16, chunkSize uint16) (*core.CHUNK, error) {
	nodeConfig, err := krsDB.GetNodeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get node config: %v", err)
	}

	// Use KDC address from config, fallback to database if not in config
	kdcAddress := conf.Node.KdcAddress
	if kdcAddress == "" {
		kdcAddress = nodeConfig.KdcAddress
	}
	if kdcAddress == "" {
		return nil, fmt.Errorf("KDC address not configured")
	}

	// Build QNAME: <nodeid><distributionID>.<controlzone>
	// For manifest (sequence 0): node.distid.control.
	// For data chunks (sequence > 0): sequence.node.distid.control.
	controlZoneClean := conf.ControlZone
	if !strings.HasSuffix(controlZoneClean, ".") {
		controlZoneClean += "."
	}
	// Ensure nodeID is FQDN
	nodeIDFQDN := nodeID
	if !strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDFQDN = dns.Fqdn(nodeID)
	}

	var qname string
	if sequence == 0 {
		// Manifest chunk
		qname = fmt.Sprintf("%s%s.%s", nodeIDFQDN, distributionID, controlZoneClean)
	} else {
		// Data chunk
		qname = fmt.Sprintf("%d.%s%s.%s", sequence, nodeIDFQDN, distributionID, controlZoneClean)
	}

	// Create CHUNK query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, core.TypeCHUNK)
	msg.RecursionDesired = false
	// Set EDNS0 to allow larger messages
	msg.SetEdns0(dns.DefaultMsgSize, true)

	if sequence == 0 {
		log.Printf("KRS: Querying CHUNK manifest for node %s, distribution %s", nodeID, distributionID)
		log.Printf("KRS: CHUNK query: QNAME=%s, QTYPE=CHUNK", qname)
	} else {
		log.Printf("KRS: Querying CHUNK chunk %d for node %s, distribution %s", sequence, nodeID, distributionID)
		log.Printf("KRS: CHUNK query: QNAME=%s, QTYPE=CHUNK", qname)
	}

	// UDP DNS message max size is ~1232 bytes (with EDNS0), but we need to account for
	// DNS header (~12 bytes) and QNAME (~50-100 bytes typically), leaving ~1180 bytes for payload
	// If chunk size is known and > 1180 bytes, use TCP directly
	useTCP := chunkSize > 1180 || sequence == 0 // Always use TCP for manifest (can be large)

	var resp *dns.Msg

	if useTCP {
		if sequence == 0 {
			log.Printf("KRS: Using TCP for CHUNK manifest")
		} else {
			log.Printf("KRS: Using TCP for CHUNK (chunk size %d > 1180 bytes)", chunkSize)
		}
		tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
		resp, _, err = tcpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send CHUNK query over TCP: %v", err)
		}
	} else {
		// Try UDP first
		udpClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		resp, _, err = udpClient.Exchange(msg, kdcAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to send CHUNK query: %v", err)
		}

		// Check for truncation and retry with TCP
		if resp.Truncated {
			log.Printf("KRS: CHUNK response truncated (TC=1), retrying with TCP")
			tcpClient := &dns.Client{Net: "tcp", Timeout: 10 * time.Second}
			resp, _, err = tcpClient.Exchange(msg, kdcAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to send CHUNK query over TCP: %v", err)
			}
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("CHUNK query returned rcode %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse CHUNK from response
	if len(resp.Answer) == 0 {
		return nil, fmt.Errorf("CHUNK response has no answer RRs")
	}

	rr := resp.Answer[0]
	if privRR, ok := rr.(*dns.PrivateRR); ok && privRR.Hdr.Rrtype == core.TypeCHUNK {
		if chunk, ok := privRR.Data.(*core.CHUNK); ok {
			if sequence == 0 {
				log.Printf("KRS: Parsed CHUNK manifest: format=%d, total=%d", chunk.Format, chunk.Total)
			} else {
				log.Printf("KRS: Parsed CHUNK chunk: sequence=%d, total=%d, data_length=%d", chunk.Sequence, chunk.Total, chunk.DataLength)
			}
			return chunk, nil
		}
	}

	return nil, fmt.Errorf("failed to parse CHUNK from response")
}

// ExtractManifestFromCHUNK extracts manifest data from a CHUNK manifest chunk
// This is a wrapper around distrib.ExtractManifestData for JSON format
// For JWT format, use ExtractJWTManifestFromCHUNK instead
func ExtractManifestFromCHUNK(chunk *core.CHUNK) (*distrib.ManifestData, error) {
	return distrib.ExtractManifestData(chunk)
}

// ExtractJWTManifestFromCHUNK extracts JWT manifest data from a CHUNK manifest chunk
// This verifies the JWT signature using the provided verification key
func ExtractJWTManifestFromCHUNK(chunk *core.CHUNK, verificationKey crypto.PublicKey, backend crypto.Backend) (*nmdistrib.JWTManifestData, error) {
	return nmdistrib.ExtractJWTManifestData(chunk, verificationKey, backend)
}

// ReassembleCHUNKChunks reassembles CHUNK chunks into complete data
// This is a wrapper around distrib.ReassembleCHUNKs for backward compatibility
func ReassembleCHUNKChunks(chunks []*core.CHUNK) ([]byte, error) {
	return distrib.ReassembleCHUNKs(chunks)
}

// ProcessDistribution processes a distribution using CHUNK format
func ProcessDistribution(krsDB *KrsDB, conf *tnm.KrsConf, distributionID string, processTextResult *string) error {
	// Use node ID from config file, not database
	// Ensure it's an FQDN
	nodeID := conf.Node.ID
	if nodeID == "" {
		return fmt.Errorf("node ID not configured in config file")
	}
	nodeID = dns.Fqdn(nodeID)

	log.Printf("KRS: Processing distribution %s for node %s", distributionID, nodeID)

	// Query CHUNK manifest (sequence 0)
	manifestChunk, err := QueryCHUNK(krsDB, conf, nodeID, distributionID, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to query CHUNK manifest: %v", err)
	}

	// Auto-detect manifest format and extract accordingly
	var manifestData *distrib.ManifestData
	var contentType string
	var cryptoBackend string
	var retireTime string
	var distributionTimestamp int64
	var distributionTTL time.Duration
	var chunkHash string

	if distrib.IsJWTManifest(manifestChunk) {
		// JWT format - extract with signature verification
		log.Printf("KRS: Detected JWT manifest format")

		// Determine crypto backend from JWT to load correct verification key
		// For JWT, we need to peek at the claims to determine the backend
		// Default to JOSE since JWT format typically indicates JOSE was used
		cryptoBackend = "jose"

		// Load KDC verification key
		var kdcVerificationKey crypto.PublicKey
		var backend crypto.Backend

		if cryptoBackend == "jose" && conf.Node.KdcJosePubKey != "" {
			verificationKeyData, err := loadKdcVerificationKey(conf, cryptoBackend)
			if err != nil {
				return fmt.Errorf("failed to load KDC verification key for JWT manifest: %v", err)
			}
			backend, err = crypto.GetBackend(cryptoBackend)
			if err != nil {
				return fmt.Errorf("failed to get crypto backend for JWT verification: %v", err)
			}
			kdcVerificationKey, err = backend.ParsePublicKey(verificationKeyData)
			if err != nil {
				return fmt.Errorf("failed to parse KDC verification key: %v", err)
			}
		} else {
			return fmt.Errorf("KDC verification key not configured for JWT manifest verification")
		}

		// Extract and verify JWT manifest
		jwtManifest, err := ExtractJWTManifestFromCHUNK(manifestChunk, kdcVerificationKey, backend)
		if err != nil {
			return fmt.Errorf("failed to extract and verify JWT manifest: %v", err)
		}
		log.Printf("KRS: JWT manifest signature verified successfully")

		// Extract fields from JWT claims (flattened structure)
		contentType = jwtManifest.Claims.Content
		cryptoBackend = jwtManifest.Claims.Crypto
		if cryptoBackend == "" {
			cryptoBackend = "jose" // Default for JWT format
		}
		retireTime = jwtManifest.Claims.RetireTime
		chunkHash = jwtManifest.Claims.ChunkHash
		distributionTimestamp = jwtManifest.Claims.IssuedAt

		// Parse distribution TTL
		if jwtManifest.Claims.DistributionTTL != "" {
			parsedTTL, err := time.ParseDuration(jwtManifest.Claims.DistributionTTL)
			if err != nil {
				log.Printf("KRS: Warning: Failed to parse distribution_ttl '%s', using default 5 minutes: %v", jwtManifest.Claims.DistributionTTL, err)
				distributionTTL = 5 * time.Minute
			} else {
				distributionTTL = parsedTTL
			}
		} else {
			distributionTTL = 5 * time.Minute
		}

		// Convert JWT manifest to legacy ManifestData format for processing
		manifestData = nmdistrib.ConvertJWTClaimsToManifestData(&jwtManifest.Claims, jwtManifest.Payload)

		log.Printf("KRS: Extracted JWT manifest: content=%s, crypto=%s, chunk_count=%d",
			contentType, cryptoBackend, manifestData.ChunkCount)

	} else if distrib.IsJSONManifest(manifestChunk) {
		// A JSON manifest is not signed by the KDC; only JWT manifests are accepted
		return fmt.Errorf("distribution %s has an unsigned (JSON) manifest: refused, only KDC-signed JWT manifests are accepted", distributionID)
	} else {
		return fmt.Errorf("unsupported manifest format: %d (expected JWT=%d)",
			manifestChunk.Format, core.FormatJWT)
	}

	// Validate timestamp freshness (replay protection)
	now := time.Now()
	distributionTime := time.Unix(distributionTimestamp, 0)
	age := now.Sub(distributionTime)
	if age < 0 {
		return fmt.Errorf("distribution timestamp is in the future (clock skew?): %v", distributionTime)
	}
	if age > distributionTTL {
		return fmt.Errorf("distribution is too old (age: %v, TTL: %v, timestamp: %v) - possible replay attack", age, distributionTTL, distributionTime)
	}
	log.Printf("KRS: Distribution timestamp validated: age %v (within TTL %v)", age, distributionTTL)

	log.Printf("KRS: Distribution content type: %s, chunk_count: %d", contentType, manifestData.ChunkCount)

	var reassembled []byte

	// Check if payload is included inline in manifest
	if len(manifestData.Payload) > 0 {
		// Payload is inline, use it directly
		reassembled = make([]byte, len(manifestData.Payload))
		copy(reassembled, manifestData.Payload)
		log.Printf("KRS: Using inline payload from CHUNK manifest (%d bytes)", len(reassembled))
	} else if manifestData.ChunkCount > 0 {
		// Payload is chunked, fetch all CHUNK chunks
		// Note: CHUNK uses sequence 0 for manifest, so data chunks start at sequence 1
		var chunks []*core.CHUNK
		for i := uint16(1); i <= manifestData.ChunkCount; i++ {
			chunk, err := QueryCHUNK(krsDB, conf, nodeID, distributionID, i, manifestData.ChunkSize)
			if err != nil {
				return fmt.Errorf("failed to query CHUNK chunk %d: %v", i, err)
			}
			chunks = append(chunks, chunk)
			log.Printf("KRS: Fetched CHUNK chunk %d/%d (sequence %d)", i, manifestData.ChunkCount, chunk.Sequence)
		}

		// Reassemble chunks
		var err error
		reassembled, err = ReassembleCHUNKChunks(chunks)
		if err != nil {
			return fmt.Errorf("failed to reassemble CHUNK chunks: %v", err)
		}

		log.Printf("KRS: Reassembled %d bytes from %d CHUNK chunks", len(reassembled), len(chunks))
	} else {
		return fmt.Errorf("CHUNK manifest has no payload and chunk_count is 0")
	}

	// The payload must be the one the signed manifest names: an inline payload
	// is inside the signature already, data chunks are bound to it by chunk_hash
	if chunkHash == "" {
		return fmt.Errorf("distribution %s: signed manifest carries no chunk_hash", distributionID)
	}
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256(reassembled)); got != chunkHash {
		return fmt.Errorf("distribution %s: payload hash %s does not match the signed chunk_hash %s", distributionID, got, chunkHash)
	}

	// Process based on content type
	switch contentType {
	case "clear_text":
		text, err := ProcessClearText(reassembled)
		if err != nil {
			return err
		}
		// Store text for API response (will be nil if not called from API)
		if processTextResult != nil {
			*processTextResult = text
		}
		return nil

	case "encrypted_text":
		text, err := ProcessEncryptedText(krsDB, conf, reassembled)
		if err != nil {
			return err
		}
		// Store text for API response (will be nil if not called from API)
		if processTextResult != nil {
			*processTextResult = text
		}
		return nil

	case "zonelist":
		return ProcessZoneList(krsDB, reassembled)

	case "key_operations":
		// Key operations: roll_key, delete_key
		return ProcessEncryptedOperations(krsDB, conf, reassembled, distributionID, retireTime, cryptoBackend)

	case "mgmt_operations":
		// Management operations: ping, status, etc.
		return ProcessEncryptedOperations(krsDB, conf, reassembled, distributionID, retireTime, cryptoBackend)

	case "mixed_operations":
		// Mixed operations: combination of key, node, and/or management operations
		return ProcessEncryptedOperations(krsDB, conf, reassembled, distributionID, retireTime, cryptoBackend)

	case "node_operations":
		// Node operations: update_components
		return ProcessNodeComponents(krsDB, conf, reassembled, distributionID, cryptoBackend)

	default:
		return fmt.Errorf("unknown content type: %s", contentType)
	}
}

// ProcessClearText processes clear_text content
// Returns the decoded text. If called directly (not from API), prints to stdout
func ProcessClearText(data []byte) (string, error) {
	// Data is base64-encoded, decode it
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 clear text: %v", err)
	}

	text := string(decoded)
	log.Printf("KRS: ===== CLEAR TEXT CONTENT =====")
	fmt.Println(text)
	log.Printf("KRS: ===== END CLEAR TEXT =====")

	return text, nil
}

// ProcessEncryptedText processes encrypted_text content
// Displays base64 transport, ciphertext, and decrypted cleartext
func ProcessEncryptedText(krsDB *KrsDB, conf *tnm.KrsConf, data []byte) (string, error) {
	// Step 1: Display base64 transport encoded message
	log.Printf("KRS: ===== ENCRYPTED TEXT CONTENT =====")
	log.Printf("KRS: --- Base64 Transport Encoded (as received, %d bytes) ---", len(data))
	fmt.Println(string(data))
	fmt.Println()

	// Step 2: Decode base64 to get ciphertext
	log.Printf("KRS: Decoding base64...")
	ciphertextBase64, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 encrypted text: %v", err)
	}
	log.Printf("KRS: Base64 decoded to %d bytes", len(ciphertextBase64))

	log.Printf("KRS: --- Ciphertext (base64 removed, %d bytes) ---", len(ciphertextBase64))
	// Display first 64 bytes as hex for readability (full ciphertext might be very long)
	if len(ciphertextBase64) > 64 {
		fmt.Printf("%x... (truncated, showing first 64 bytes)\n", ciphertextBase64[:64])
	} else {
		fmt.Printf("%x\n", ciphertextBase64)
	}
	fmt.Println()

	// Step 3: Verify the KDC signature and decrypt with the node's JOSE key
	plaintext, err := decryptPayload(conf, data, "jose")
	if err != nil {
		return "", fmt.Errorf("failed to decrypt encrypted text: %v", err)
	}
	log.Printf("KRS: JOSE decryption successful: %d bytes decrypted", len(plaintext))

	// Step 4: Display decrypted cleartext
	log.Printf("KRS: --- Cleartext (after JOSE decryption, %d bytes) ---", len(plaintext))
	text := string(plaintext)
	fmt.Println(text)
	log.Printf("KRS: ===== END ENCRYPTED TEXT =====")

	return text, nil
}

// ProcessZoneList processes zonelist content (JSON array of zone names)
func ProcessZoneList(krsDB *KrsDB, data []byte) error {
	// Data is base64-encoded JSON, decode it
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("failed to decode base64 zone list: %v", err)
	}

	var zones []string
	if err := json.Unmarshal(decoded, &zones); err != nil {
		return fmt.Errorf("failed to unmarshal zone list JSON: %v", err)
	}

	log.Printf("KRS: Received zone list with %d zones", len(zones))
	for _, zone := range zones {
		log.Printf("KRS:   - %s", zone)
	}

	// TODO: Process zone list
	return nil
}

// decryptPayload decrypts an encrypted payload using the appropriate crypto backend
// Handles backend defaulting, validation, key loading, and signature verification
// Returns the decrypted plaintext or an error
func decryptPayload(conf *tnm.KrsConf, data []byte, cryptoBackend string) ([]byte, error) {
	// Default to JOSE if crypto backend not specified
	if cryptoBackend == "" {
		cryptoBackend = "jose"
	}

	privateKey, err := loadPrivateKeyForBackend(conf, cryptoBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key for %s backend: %v", cryptoBackend, err)
	}
	log.Printf("KRS: Loaded node private key for %s backend (%d bytes)", cryptoBackend, len(privateKey))

	// Get the crypto backend
	backend, err := crypto.GetBackend(cryptoBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto backend %s: %v", cryptoBackend, err)
	}

	// Load the KDC verification key: every payload must carry the KDC's signature
	verificationKeyData, err := loadKdcVerificationKey(conf, cryptoBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to load KDC %s verification key: %v", cryptoBackend, err)
	}
	kdcVerificationKey, err := backend.ParsePublicKey(verificationKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KDC %s verification key: %v", cryptoBackend, err)
	}

	// Parse the private key using the backend
	privKey, err := backend.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key with %s backend: %v", backend.Name(), err)
	}

	// Verify the JWS signature, then decrypt the JWE: JWS(JWE(payload))
	plaintextJSON, err := nmdistrib.DecodeDecryptAndVerify(backend, privKey, kdcVerificationKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt and verify distribution payload with %s backend: %v", backend.Name(), err)
	}
	log.Printf("KRS: Verified signature and decrypted distribution payload using %s backend: %d bytes", backend.Name(), len(plaintextJSON))

	return plaintextJSON, nil
}

// ProcessEncryptedOperations processes operation-based distributions
// Handles: key_operations, mgmt_operations, mixed_operations
// Data is base64-encoded encrypted payload containing operation entries in JSON
// The payload format: <ephemeral_pub_key (32 bytes)><ciphertext>
// Operations can be: roll_key, delete_key (key operations), ping (management operations), or mixed
// distributionID and retireTime are optional and can be passed from the manifest metadata
func ProcessEncryptedOperations(krsDB *KrsDB, conf *tnm.KrsConf, data []byte, distributionID string, retireTime string, cryptoBackend string) error {
	distID := distributionID
	// Step 1: Load node's private key and decrypt payload
	log.Printf("KRS: Processing operation-based distribution (key_operations, mgmt_operations, or mixed) (%d bytes base64)", len(data))

	plaintextJSON, err := decryptPayload(conf, data, cryptoBackend)
	if err != nil {
		return err
	}

	// Step 3: Parse JSON structure as operation-based distribution entries
	var entries []tnm.DistributionEntry
	if err := json.Unmarshal(plaintextJSON, &entries); err != nil {
		return fmt.Errorf("failed to unmarshal decrypted operations JSON: %v", err)
	}

	log.Printf("KRS: Parsed %d operation entries from decrypted payload", len(entries))

	// Debug logging: log cleartext content (masking private keys)
	if tdns.Globals.Debug {
		logEntries := make([]map[string]interface{}, len(entries))
		for i, entry := range entries {
			logEntry := map[string]interface{}{
				"operation": entry.Operation,
				"zone_name": entry.ZoneName,
				"key_id":    entry.KeyID,
			}
			if entry.Operation == "roll_key" {
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
		log.Printf("KRS: DEBUG: Decrypted distribution payload (private keys masked): %s", string(logJSON))
	}

	// Step 4: Process each operation entry by routing to appropriate handler
	successCount := 0
	var successfulKeys []edns0.KeyStatusEntry
	var failedKeys []edns0.KeyStatusEntry

	for i, entry := range entries {
		log.Printf("KRS: Processing operation %d/%d: operation=%s, zone=%s, key_id=%s", i+1, len(entries), entry.Operation, entry.ZoneName, entry.KeyID)

		// Route operation to appropriate handler
		var opErr error
		switch entry.Operation {
		case "ping":
			opErr = handlePingOperation(entry, i)
			if opErr == nil {
				successCount++
				successfulKeys = append(successfulKeys, edns0.KeyStatusEntry{
					ZoneName: "ping",
					KeyID:    fmt.Sprintf("op-%d", i),
				})
			} else {
				failedKeys = append(failedKeys, edns0.KeyStatusEntry{
					ZoneName: "ping",
					KeyID:    fmt.Sprintf("op-%d", i),
					Error:    opErr.Error(),
				})
			}

		case "roll_key":
			opErr = handleRollKeyOperation(krsDB, entry, distID, retireTime, i)
			if opErr == nil {
				successCount++
				successfulKeys = append(successfulKeys, edns0.KeyStatusEntry{
					ZoneName: entry.ZoneName,
					KeyID:    entry.KeyID,
				})
			} else {
				failedKeys = append(failedKeys, edns0.KeyStatusEntry{
					ZoneName: entry.ZoneName,
					KeyID:    entry.KeyID,
					Error:    opErr.Error(),
				})
			}

		case "delete_key":
			opErr = handleDeleteKeyOperation(krsDB, entry, i)
			if opErr == nil {
				successCount++
				successfulKeys = append(successfulKeys, edns0.KeyStatusEntry{
					ZoneName: entry.ZoneName,
					KeyID:    entry.KeyID,
				})
			} else {
				failedKeys = append(failedKeys, edns0.KeyStatusEntry{
					ZoneName: entry.ZoneName,
					KeyID:    entry.KeyID,
					Error:    opErr.Error(),
				})
			}

		default:
			log.Printf("KRS: Warning: Unknown operation type '%s' for entry %d", entry.Operation, i+1)
			failedKeys = append(failedKeys, edns0.KeyStatusEntry{
				ZoneName: entry.ZoneName,
				KeyID:    entry.KeyID,
				Error:    fmt.Sprintf("Unknown operation: %s", entry.Operation),
			})
		}
	}

	log.Printf("KRS: Successfully processed %d/%d operations", successCount, len(entries))
	if successCount == 0 {
		return fmt.Errorf("failed to process any operations")
	}

	// Send confirmation NOTIFY back to KDC
	// Get KDC address from config
	kdcAddress := conf.Node.KdcAddress
	if kdcAddress == "" {
		// Fallback to database
		nodeConfig, err := krsDB.GetNodeConfig()
		if err == nil && nodeConfig.KdcAddress != "" {
			kdcAddress = nodeConfig.KdcAddress
		}
	}

	if kdcAddress != "" && distID != "" {
		// Send confirmation asynchronously (don't block on network I/O)
		// Capture distID and key status in closure
		distIDCopy := distID
		successfulKeysCopy := successfulKeys
		failedKeysCopy := failedKeys
		go func() {
			if err := SendConfirmationToKDC(distIDCopy, conf.ControlZone, kdcAddress, successfulKeysCopy, failedKeysCopy); err != nil {
				log.Printf("KRS: Warning: Failed to send confirmation NOTIFY: %v", err)
			} else {
				log.Printf("KRS: Successfully sent confirmation NOTIFY for distribution %s", distIDCopy)
			}
		}()
	} else {
		if distID == "" {
			log.Printf("KRS: Warning: Distribution ID not available, cannot send confirmation NOTIFY")
		} else {
			log.Printf("KRS: Warning: KDC address not configured, cannot send confirmation NOTIFY")
		}
	}

	return nil
}

// ProcessNodeComponents processes node_operations content (update_components operations)
// Data is base64-encoded encrypted payload containing the component list
// The payload format: <ephemeral_pub_key (32 bytes)><ciphertext>
// distributionID is optional and can be passed from the manifest metadata
func ProcessNodeComponents(krsDB *KrsDB, conf *tnm.KrsConf, data []byte, distributionID string, cryptoBackend string) error {
	distID := distributionID
	// Step 1: Load node's private key and decrypt payload
	log.Printf("KRS: Processing node_operations content (update_components) (%d bytes base64)", len(data))

	plaintextJSON, err := decryptPayload(conf, data, cryptoBackend)
	if err != nil {
		return err
	}

	// Step 3: Parse JSON structure (cleartext)
	type ComponentEntry struct {
		ComponentID string `json:"component_id"`
	}

	var entries []ComponentEntry
	if err := json.Unmarshal(plaintextJSON, &entries); err != nil {
		return fmt.Errorf("failed to unmarshal decrypted components JSON: %v", err)
	}

	log.Printf("KRS: Parsed %d component entries from decrypted payload", len(entries))

	// Step 4: Store component assignments in the database
	componentIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		componentIDs = append(componentIDs, entry.ComponentID)
		log.Printf("KRS: Node should serve component: %s", entry.ComponentID)
	}

	log.Printf("KRS: Node component list updated: %d component(s) - %v", len(componentIDs), componentIDs)
	log.Printf("KRS: Distribution ID: %s", distID)

	// Store components in the database
	var successfulComponents []edns0.ComponentStatusEntry
	var failedComponents []edns0.ComponentStatusEntry

	for _, componentID := range componentIDs {
		// For now, assume all components succeed (we could add error handling later)
		successfulComponents = append(successfulComponents, edns0.ComponentStatusEntry{
			ComponentID: componentID,
		})
	}

	if err := krsDB.StoreNodeComponents(componentIDs, distID); err != nil {
		log.Printf("KRS: Warning: Failed to store components in database: %v", err)
		// Mark all components as failed if storage fails
		failedComponents = successfulComponents
		successfulComponents = nil
		for i := range failedComponents {
			failedComponents[i].Error = err.Error()
		}
	}

	// Send confirmation NOTIFY back to KDC
	// Get KDC address from config
	kdcAddress := conf.Node.KdcAddress
	if kdcAddress == "" {
		// Fallback to database
		nodeConfig, err := krsDB.GetNodeConfig()
		if err == nil && nodeConfig.KdcAddress != "" {
			kdcAddress = nodeConfig.KdcAddress
		}
	}

	if kdcAddress != "" && distID != "" {
		// Send confirmation asynchronously (don't block on network I/O)
		// Capture distID and component status in closure
		distIDCopy := distID
		successfulComponentsCopy := successfulComponents
		failedComponentsCopy := failedComponents
		go func() {
			if err := SendComponentConfirmationToKDC(distIDCopy, conf.ControlZone, kdcAddress, successfulComponentsCopy, failedComponentsCopy); err != nil {
				log.Printf("KRS: Warning: Failed to send component confirmation NOTIFY: %v", err)
			} else {
				log.Printf("KRS: Successfully sent component confirmation NOTIFY for distribution %s", distIDCopy)
			}
		}()
	} else {
		if distID == "" {
			log.Printf("KRS: Warning: Distribution ID not available, cannot send component confirmation NOTIFY")
		} else {
			log.Printf("KRS: Warning: KDC address not configured, cannot send component confirmation NOTIFY")
		}
	}

	return nil
}

// loadPrivateKeyForBackend loads the appropriate private key based on the crypto backend
// For JOSE: loads JWK JSON from LongTermJosePrivKey
func loadPrivateKeyForBackend(conf *tnm.KrsConf, cryptoBackend string) ([]byte, error) {
	if cryptoBackend == "jose" {
		// Load JOSE private key (JWK JSON format)
		if conf.Node.LongTermJosePrivKey == "" {
			return nil, fmt.Errorf("node long-term JOSE private key not configured (required for JOSE backend)")
		}

		// Read JOSE key file
		keyData, err := os.ReadFile(conf.Node.LongTermJosePrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read JOSE private key file %s: %v", conf.Node.LongTermJosePrivKey, err)
		}

		// Parse key (skip comments, extract JSON)
		// Preserve line breaks for multi-line pretty-printed JWK JSON
		keyLines := strings.Split(string(keyData), "\n")
		var jsonLines []string
		for _, line := range keyLines {
			trimmedLine := strings.TrimSpace(line)
			if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
				// Preserve original line (with indentation) for pretty-printed JSON
				jsonLines = append(jsonLines, line)
			}
		}

		if len(jsonLines) == 0 {
			return nil, fmt.Errorf("could not find JOSE private key JSON in file %s", conf.Node.LongTermJosePrivKey)
		}

		// Join lines with newlines to preserve formatting
		jwkJSON := strings.Join(jsonLines, "\n")

		log.Printf("KRS: Loaded JOSE private key from %s (%d bytes JSON)", conf.Node.LongTermJosePrivKey, len(jwkJSON))
		return []byte(jwkJSON), nil
	}
	return nil, fmt.Errorf("unsupported crypto backend: %s", cryptoBackend)
}

// CheckKdcVerificationKey checks that the KDC's JOSE public key is configured,
// readable and parseable. Every distribution is verified with it, so a KRS
// without it can receive nothing.
func CheckKdcVerificationKey(conf *tnm.KrsConf) error {
	keyData, err := loadKdcVerificationKey(conf, "jose")
	if err != nil {
		return err
	}
	backend, err := crypto.GetBackend("jose")
	if err != nil {
		return fmt.Errorf("failed to get JOSE backend: %v", err)
	}
	if _, err := backend.ParsePublicKey(keyData); err != nil {
		return fmt.Errorf("failed to parse KDC JOSE public key %s: %v", conf.Node.KdcJosePubKey, err)
	}
	return nil
}

// loadKdcVerificationKey loads the KDC's public key for signature verification
// This is used to verify JWS signatures on distributions
func loadKdcVerificationKey(conf *tnm.KrsConf, cryptoBackend string) ([]byte, error) {
	if cryptoBackend == "jose" {
		// Load KDC JOSE public key (JWK JSON format)
		if conf.Node.KdcJosePubKey == "" {
			return nil, fmt.Errorf("KDC JOSE public key not configured (kdc_jose_pubkey)")
		}

		// Read KDC JOSE public key file
		keyData, err := os.ReadFile(conf.Node.KdcJosePubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read KDC JOSE public key file %s: %v", conf.Node.KdcJosePubKey, err)
		}

		// Parse key (skip comments, extract JSON)
		keyLines := strings.Split(string(keyData), "\n")
		var jsonLines []string
		for _, line := range keyLines {
			trimmedLine := strings.TrimSpace(line)
			if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
				// Preserve original line for pretty-printed JSON
				jsonLines = append(jsonLines, line)
			}
		}

		if len(jsonLines) == 0 {
			return nil, fmt.Errorf("could not find KDC JOSE public key JSON in file %s", conf.Node.KdcJosePubKey)
		}

		// Join lines with newlines to preserve formatting
		jwkJSON := strings.Join(jsonLines, "\n")

		log.Printf("KRS: Loaded KDC JOSE verification key from %s (%d bytes JSON)", conf.Node.KdcJosePubKey, len(jwkJSON))
		return []byte(jwkJSON), nil
	} else {
		return nil, fmt.Errorf("unsupported crypto backend for verification key: %s", cryptoBackend)
	}
}

// handlePingOperation processes a ping operation
func handlePingOperation(entry tnm.DistributionEntry, index int) error {
	log.Printf("KRS: Processing ping operation (entry %d)", index+1)

	// Extract nonce from metadata
	if entry.Metadata == nil {
		return fmt.Errorf("ping operation missing metadata")
	}

	nonce, ok := entry.Metadata["nonce"].(string)
	if !ok || nonce == "" {
		return fmt.Errorf("ping operation missing nonce in metadata")
	}

	timestamp, ok := entry.Metadata["timestamp"].(string)
	if !ok || timestamp == "" {
		log.Printf("KRS: Warning: Ping operation missing timestamp in metadata")
	}

	log.Printf("KRS: Ping operation successful - nonce: %s, timestamp: %s", nonce, timestamp)
	return nil
}

// handleRollKeyOperation processes a roll_key operation
func handleRollKeyOperation(krsDB *KrsDB, entry tnm.DistributionEntry, distID, retireTime string, index int) error {
	log.Printf("KRS: Processing roll_key operation (entry %d): zone=%s, key_id=%s", index+1, entry.ZoneName, entry.KeyID)

	// Parse key_id as uint16
	var keyID uint16
	if _, err := fmt.Sscanf(entry.KeyID, "%d", &keyID); err != nil {
		if _, err2 := fmt.Sscanf(entry.KeyID, "%x", &keyID); err2 != nil {
			return fmt.Errorf("could not parse key_id '%s' as number", entry.KeyID)
		}
	}

	// Decode private key from base64 string
	privateKeyBytes, err := base64.StdEncoding.DecodeString(entry.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode private_key: %v", err)
	}

	// Determine state based on key type
	// ZSKs go to "edgesigner" state, KSKs go to "active" state
	keyState := "edgesigner"
	isKSK := false
	if entry.KeyType == "KSK" || entry.Flags == 257 {
		keyState = "active"
		isKSK = true
		log.Printf("KRS: Detected KSK (KeyType: '%s', Flags: %d)", entry.KeyType, entry.Flags)
	} else {
		log.Printf("KRS: Detected ZSK (KeyType: '%s', Flags: %d)", entry.KeyType, entry.Flags)
	}

	receivedKey := &ReceivedKey{
		ID:             fmt.Sprintf("%s-%s", entry.ZoneName, entry.KeyID),
		ZoneName:       entry.ZoneName,
		KeyID:          keyID,
		KeyType:        entry.KeyType,
		Algorithm:      entry.Algorithm,
		Flags:          entry.Flags,
		PublicKey:      entry.PublicKey,
		PrivateKey:     privateKeyBytes,
		State:          keyState,
		ReceivedAt:     time.Now(),
		DistributionID: distID,
		RetireTime:     retireTime,
		Comment:        "Received via roll_key operation",
	}

	// Store in database atomically
	var storeErr error
	if isKSK {
		receivedKey.KeyType = "KSK"
		storeErr = krsDB.AddActiveKeyWithRetirement(receivedKey)
		if storeErr != nil {
			return fmt.Errorf("failed to store KSK: %v", storeErr)
		}
		log.Printf("KRS: Successfully stored KSK (key_id %d) in 'active' state for zone %s", keyID, entry.ZoneName)
	} else {
		receivedKey.KeyType = "ZSK"
		storeErr = krsDB.AddEdgesignerKeyWithRetirement(receivedKey)
		if storeErr != nil {
			return fmt.Errorf("failed to store ZSK: %v", storeErr)
		}
		log.Printf("KRS: Successfully stored ZSK (key_id %d) in 'edgesigner' state for zone %s", keyID, entry.ZoneName)
	}

	// Check if this is a key rollover (old_key_id specified)
	if entry.Metadata != nil {
		if oldKeyIDStr, ok := entry.Metadata["old_key_id"].(string); ok && oldKeyIDStr != "" {
			// Retire the old key
			log.Printf("KRS: Rolling key - retiring old key %s for zone %s", oldKeyIDStr, entry.ZoneName)

			// Parse old key ID as uint16
			var oldKeyIDUint uint16
			if _, err := fmt.Sscanf(oldKeyIDStr, "%d", &oldKeyIDUint); err != nil {
				log.Printf("KRS: Warning: Could not parse old_key_id '%s' as number: %v", oldKeyIDStr, err)
			} else {
				// Find and retire the old key
				oldKey, err := krsDB.GetReceivedKeyByZoneAndKeyID(entry.ZoneName, oldKeyIDUint)
				if err != nil {
					log.Printf("KRS: Warning: Could not find old key %s to retire: %v", oldKeyIDStr, err)
					// Not fatal - new key is already stored
				} else {
					now := time.Now()
					if err := krsDB.UpdateReceivedKeyState(oldKey.ID, "retired", nil, &now); err != nil {
						log.Printf("KRS: Warning: Failed to retire old key %s: %v", oldKeyIDStr, err)
					} else {
						log.Printf("KRS: Successfully retired old key %s", oldKeyIDStr)
					}
				}
			}
		}
	}

	return nil
}

// handleDeleteKeyOperation processes a delete_key operation
// This operation is idempotent: it succeeds whether or not the key exists
func handleDeleteKeyOperation(krsDB *KrsDB, entry tnm.DistributionEntry, index int) error {
	log.Printf("KRS: Processing delete_key operation (entry %d): zone=%s, key_id=%s", index+1, entry.ZoneName, entry.KeyID)

	// Log reason if provided (do this before deletion attempt)
	if entry.Metadata != nil {
		if reason, ok := entry.Metadata["reason"].(string); ok && reason != "" {
			log.Printf("KRS: Deletion reason: %s", reason)
		}
	}

	// Delete the key from local storage
	err := krsDB.DeleteReceivedKeyByZoneAndKeyID(entry.ZoneName, entry.KeyID)
	if err != nil {
		// Check if it's a "not found" error - this is idempotent success
		if strings.Contains(err.Error(), "not found") {
			log.Printf("KRS: Key %s not found in zone %s (idempotent delete - key may have been deleted already)", entry.KeyID, entry.ZoneName)
			return nil
		}
		// Actual error - return it
		return fmt.Errorf("failed to delete key: %v", err)
	}

	log.Printf("KRS: Successfully deleted key %s for zone %s", entry.KeyID, entry.ZoneName)

	return nil
}
