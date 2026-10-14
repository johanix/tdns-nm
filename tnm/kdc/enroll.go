/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Enrollment blob generation and management
 */

package kdc

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Auto-register JOSE backend
	"github.com/johanix/tdns-transport/v2/hpke"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// EnrollmentBlob represents the enrollment blob structure
type EnrollmentBlob struct {
	Token                string `json:"token"`                  // Enrollment token value
	NodeID               string `json:"node_id"`                // Node ID
	KdcHpkePubKey        string `json:"kdc_hpke_pubkey"`        // KDC HPKE public key (hex encoded)
	KdcJosePubKey        string `json:"kdc_jose_pubkey"`        // KDC JOSE public key (JWK JSON, base64 encoded for transport)
	KdcEnrollmentAddress string `json:"kdc_enrollment_address"` // KDC enrollment address (IP:port)
	ControlZone          string `json:"control_zone"`           // Control zone name
}

// GenerateEnrollmentBlobContent generates the enrollment blob content (base64-encoded JSON)
// nodeID: The node ID
// token: The enrollment token
// kdcConf: KDC configuration
// cryptoBackend: Optional crypto backend ("hpke" or "jose"). If empty, both are included.
// Returns: base64-encoded blob content, error
func GenerateEnrollmentBlobContent(nodeID string, token *EnrollmentToken, kdcConf *tnm.KdcConf, cryptoBackend string) (string, error) {
	// Validate required configuration fields
	if kdcConf.KdcEnrollmentAddress == "" {
		return "", fmt.Errorf("kdc_enrollment_address is not configured in KDC config file - this is required for enrollment blob generation")
	}
	if kdcConf.ControlZone == "" {
		return "", fmt.Errorf("control_zone is not configured in KDC config file - this is required for enrollment blob generation")
	}

	// Validate crypto backend if specified
	if cryptoBackend != "" && cryptoBackend != "hpke" && cryptoBackend != "jose" {
		return "", fmt.Errorf("invalid crypto backend: %s (must be 'hpke' or 'jose')", cryptoBackend)
	}

	var kdcHpkePubKeyHex string
	var kdcJosePubKeyB64 string

	// Include HPKE key if cryptoBackend is "hpke" or if cryptoBackend is empty and HPKE is configured
	if cryptoBackend == "hpke" || (cryptoBackend == "" && kdcConf.KdcHpkePrivKey != "") {
		// Get KDC HPKE public key
		kdcHpkePubKey, err := GetKdcHpkePubKey(kdcConf.KdcHpkePrivKey)
		if err != nil {
			return "", fmt.Errorf("failed to get KDC HPKE public key: %v", err)
		}
		kdcHpkePubKeyHex = hex.EncodeToString(kdcHpkePubKey)
	}

	// Include JOSE key if cryptoBackend is "jose" or if cryptoBackend is empty and JOSE is configured
	if cryptoBackend == "jose" || (cryptoBackend == "" && kdcConf.KdcJosePrivKey != "") {
		// Get KDC JOSE public key
		kdcJosePubKeyBytes, err := GetKdcJosePubKey(kdcConf.KdcJosePrivKey)
		if err != nil {
			return "", fmt.Errorf("failed to get KDC JOSE public key: %v", err)
		}
		// JOSE public key is already JWK JSON, base64-encode it for JSON transport
		kdcJosePubKeyB64 = base64.StdEncoding.EncodeToString(kdcJosePubKeyBytes)
	}

	// At least one key must be present
	if kdcHpkePubKeyHex == "" && kdcJosePubKeyB64 == "" {
		return "", fmt.Errorf("at least one crypto backend (hpke or jose) must be configured")
	}

	// Create enrollment blob structure
	blob := EnrollmentBlob{
		Token:                token.TokenValue,
		NodeID:               nodeID,
		KdcHpkePubKey:        kdcHpkePubKeyHex,
		KdcJosePubKey:        kdcJosePubKeyB64,
		KdcEnrollmentAddress: kdcConf.KdcEnrollmentAddress,
		ControlZone:          kdcConf.ControlZone,
	}

	// Marshal to JSON
	blobJSON, err := json.Marshal(blob)
	if err != nil {
		return "", fmt.Errorf("failed to marshal enrollment blob: %v", err)
	}

	// Base64 encode JSON
	blobBase64 := base64.StdEncoding.EncodeToString(blobJSON)

	return blobBase64, nil
}

// GenerateEnrollmentBlob generates an enrollment blob file for a node
// nodeID: The node ID
// token: The enrollment token
// kdcConf: KDC configuration
// outDir: Output directory (must exist)
// Returns: path to generated file, error
func GenerateEnrollmentBlob(nodeID string, token *EnrollmentToken, kdcConf *tnm.KdcConf, outDir string) (string, error) {
	// Verify output directory exists
	info, err := os.Stat(outDir)
	if err != nil {
		return "", fmt.Errorf("output directory does not exist or is not accessible: %v", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("output path is not a directory: %s", outDir)
	}

	// Generate blob content (include both keys by default)
	blobBase64, err := GenerateEnrollmentBlobContent(nodeID, token, kdcConf, "")
	if err != nil {
		return "", err
	}

	// Write to file in output directory (with newline at end)
	// Use 0600 permissions (owner read/write only) for security - enrollment blobs contain sensitive tokens
	filename := filepath.Join(outDir, fmt.Sprintf("%s.enroll", nodeID))
	blobContent := []byte(blobBase64)
	blobContent = append(blobContent, '\n') // Add newline at end
	if err := os.WriteFile(filename, blobContent, 0600); err != nil {
		return "", fmt.Errorf("failed to write enrollment blob file: %v", err)
	}

	// Get absolute path
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return filename, nil // Return relative path if absolute fails
	}

	return absPath, nil
}

// ParseEnrollmentBlob parses an enrollment blob file
// filename: Path to enrollment blob file
// Returns: EnrollmentBlob, error
func ParseEnrollmentBlob(filename string) (*EnrollmentBlob, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read enrollment blob file: %v", err)
	}

	// Process file content: skip comment lines and extract base64 content
	lines := strings.Split(string(data), "\n")
	var blobBase64Lines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comment lines (starting with #)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		blobBase64Lines = append(blobBase64Lines, line)
	}

	if len(blobBase64Lines) == 0 {
		return nil, fmt.Errorf("no base64 content found in enrollment blob file")
	}

	// Join all non-comment lines (base64 can span multiple lines)
	blobBase64 := strings.Join(blobBase64Lines, "")

	// Base64 decode
	blobJSON, err := base64.StdEncoding.DecodeString(blobBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	// Unmarshal JSON
	var blob EnrollmentBlob
	if err := json.Unmarshal(blobJSON, &blob); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return &blob, nil
}

// EnrollmentRequest represents the decrypted enrollment request from a node
type EnrollmentRequest struct {
	HpkePubKey    string `json:"hpke_pubkey"`    // HPKE public key (hex encoded)
	JosePubKey    string `json:"jose_pubkey"`    // JOSE public key (JWK JSON)
	Sig0PubKey    string `json:"sig0_pubkey"`    // SIG(0) public key (DNSKEY RR format)
	AuthToken     string `json:"auth_token"`     // Enrollment token
	Timestamp     string `json:"timestamp"`      // ISO 8601 timestamp
	NotifyAddress string `json:"notify_address"` // Optional: IP:port for NOTIFY
}

// HandleEnrollmentUpdate handles enrollment DNS UPDATE requests
// This is called by the UPDATE handler registration API when an enrollment UPDATE is detected
func HandleEnrollmentUpdate(ctx context.Context, dur *tdns.DnsUpdateRequest, kdcDB *KdcDB, kdcConf *tnm.KdcConf) error {
	w := dur.ResponseWriter
	r := dur.Msg
	zone := dur.Qname // Zone is in the question section for UPDATE

	log.Printf("KDC: Enrollment UPDATE received for zone %s from %s", zone, w.RemoteAddr())

	// Create response message
	m := new(dns.Msg)
	m.SetReply(r)

	// Helper function to return error with CHUNK option containing error details
	// hpkePubKey can be nil if we don't have it yet (e.g., decryption failed)
	// nodeID can be empty if we don't know it yet
	returnError := func(rcode int, errorMsg string, nodeID string, hpkePubKey []byte, kdcKeys *KdcHpkeKeys) error {
		m.SetRcode(r, rcode)

		// Create error confirmation
		errorConfirmation := edns0.EnrollmentConfirmation{
			NodeID:       nodeID,
			Status:       "error",
			ErrorMessage: errorMsg,
			Timestamp:    time.Now().Format(time.RFC3339),
		}

		errorJSON, err := json.Marshal(errorConfirmation)
		if err != nil {
			log.Printf("KDC: Failed to marshal error confirmation: %v", err)
			return w.WriteMsg(m)
		}

		var encryptedError []byte
		// If we have the node's HPKE pubkey, encrypt the error message
		// Otherwise, send it unencrypted (error messages aren't sensitive)
		if len(hpkePubKey) == 32 && kdcKeys != nil {
			// Encrypt using HPKE Auth mode (same as success case)
			encryptedError, err = hpke.EncryptAuth(kdcKeys.PrivateKey, hpkePubKey, errorJSON)
			if err != nil {
				log.Printf("KDC: Failed to encrypt error confirmation: %v (sending unencrypted)", err)
				encryptedError = errorJSON // Fallback to unencrypted
			}
		} else {
			// No node pubkey available, send unencrypted
			encryptedError = errorJSON
		}

		chunkOpt, err := edns0.CreateEnrollmentConfirmationOption(encryptedError)
		if err != nil {
			log.Printf("KDC: Failed to create error confirmation option: %v", err)
			return w.WriteMsg(m)
		}

		if err := edns0.AddChunkOptionToMessage(m, chunkOpt); err != nil {
			log.Printf("KDC: Failed to add error confirmation option: %v", err)
			return w.WriteMsg(m)
		}

		log.Printf("KDC: Returning error response: %s", errorMsg)
		return w.WriteMsg(m)
	}

	// Get KDC HPKE keypair early (needed for error responses and HPKE decryption)
	// HPKE keys are optional for JOSE-only KDCs
	var kdcHpkeKeys *KdcHpkeKeys
	if kdcConf.KdcHpkePrivKey != "" {
		var err error
		kdcHpkeKeys, err = GetKdcHpkeKeypair(kdcConf.KdcHpkePrivKey)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get KDC HPKE keypair: %v", err)
			log.Printf("KDC: Continuing without HPKE keys (JOSE-only KDC mode)")
			kdcHpkeKeys = nil
		}
	} else {
		log.Printf("KDC: kdc_hpke_priv_key not configured, operating in JOSE-only mode")
		kdcHpkeKeys = nil
	}
	// JOSE keys will be loaded lazily only if HPKE decryption fails or HPKE is unavailable

	// 1. Check if UPDATE section has exactly one CHUNK record
	if len(r.Ns) != 1 {
		log.Printf("KDC: Enrollment UPDATE must have exactly one RR in update section, got %d", len(r.Ns))
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Enrollment UPDATE must have exactly one RR in update section, got %d", len(r.Ns)), "", nil, kdcHpkeKeys)
	}

	// 2. Extract CHUNK record
	rr := r.Ns[0]
	if rr.Header().Rrtype != core.TypeCHUNK {
		log.Printf("KDC: Enrollment UPDATE must contain CHUNK record, got %s", dns.TypeToString[rr.Header().Rrtype])
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Enrollment UPDATE must contain CHUNK record, got %s", dns.TypeToString[rr.Header().Rrtype]), "", nil, kdcHpkeKeys)
	}

	// Check name pattern: should be _enroll.{control_zone}
	updateName := rr.Header().Name
	if !strings.HasPrefix(updateName, "_enroll.") {
		log.Printf("KDC: Enrollment UPDATE name must start with '_enroll.', got %s", updateName)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Enrollment UPDATE name must start with '_enroll.', got %s", updateName), "", nil, kdcHpkeKeys)
	}

	// Extract CHUNK data
	chunkRR, ok := rr.(*dns.PrivateRR)
	if !ok {
		log.Printf("KDC: Failed to cast RR to PrivateRR")
		return returnError(dns.RcodeFormatError, "Failed to parse CHUNK record", "", nil, kdcHpkeKeys)
	}

	chunk, ok := chunkRR.Data.(*core.CHUNK)
	if !ok {
		log.Printf("KDC: Failed to cast CHUNK data")
		return returnError(dns.RcodeFormatError, "Failed to parse CHUNK data", "", nil, kdcHpkeKeys)
	}

	// Validate CHUNK format: Sequence=0 (enrollment manifest), HMACLen=0
	// Note: Total can be 0 (enrollment with no data chunks) or >0 (enrollment with data chunks)
	if chunk.Sequence != 0 || chunk.HMACLen != 0 {
		log.Printf("KDC: Invalid CHUNK format for enrollment: Sequence=%d, HMACLen=%d", chunk.Sequence, chunk.HMACLen)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Invalid CHUNK format for enrollment: Sequence=%d, HMACLen=%d (Sequence must be 0, HMACLen must be 0)", chunk.Sequence, chunk.HMACLen), "", nil, kdcHpkeKeys)
	}

	// 3. Extract encrypted enrollment request from CHUNK data
	encryptedData := chunk.Data
	if len(encryptedData) == 0 {
		log.Printf("KDC: CHUNK data is empty")
		return returnError(dns.RcodeFormatError, "CHUNK data is empty", "", nil, kdcHpkeKeys)
	}

	// 4. Decrypt enrollment request - try HPKE first (if available), then JOSE
	// NOTE: HPKE Base mode is used for enrollment (no sender auth required)
	// JOSE encryption also doesn't require sender auth in this context
	var decryptedData []byte
	var encryptionBackend string
	var hpkeDecryptErr error

	// Try HPKE first if available
	if kdcHpkeKeys != nil {
		decryptedData, hpkeDecryptErr = hpke.Decrypt(kdcHpkeKeys.PrivateKey, nil, encryptedData)
		if hpkeDecryptErr == nil {
			encryptionBackend = "hpke"
			log.Printf("KDC: Successfully decrypted enrollment request using HPKE (decrypted length: %d)", len(decryptedData))
		} else {
			log.Printf("KDC: HPKE decryption failed, trying JOSE: %v", hpkeDecryptErr)
		}
	} else {
		log.Printf("KDC: HPKE keys not available, trying JOSE")
		hpkeDecryptErr = fmt.Errorf("HPKE keys not configured")
	}

	// If HPKE failed or unavailable, try JOSE
	if encryptionBackend == "" {
		kdcJoseKeys, err2 := GetKdcJoseKeypair(kdcConf.KdcJosePrivKey)
		if err2 != nil {
			log.Printf("KDC: Failed to get KDC JOSE keypair: %v", err2)
			var hpkeErrMsg string
			if hpkeDecryptErr != nil {
				hpkeErrMsg = hpkeDecryptErr.Error()
			} else {
				hpkeErrMsg = "HPKE keys not configured"
			}
			return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to decrypt enrollment request (tried HPKE and JOSE): HPKE error: %s, JOSE keypair error: %v", hpkeErrMsg, err2), "", nil, kdcHpkeKeys)
		}
		joseBackend, err2 := crypto.GetBackend("jose")
		if err2 != nil {
			log.Printf("KDC: Failed to get JOSE backend: %v", err2)
			var hpkeErrMsg string
			if hpkeDecryptErr != nil {
				hpkeErrMsg = hpkeDecryptErr.Error()
			} else {
				hpkeErrMsg = "HPKE keys not configured"
			}
			return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to decrypt enrollment request (tried HPKE and JOSE): HPKE error: %s, JOSE backend error: %v", hpkeErrMsg, err2), "", nil, kdcHpkeKeys)
		}
		decryptedData, err2 = joseBackend.Decrypt(kdcJoseKeys.PrivateKey, encryptedData)
		if err2 != nil {
			log.Printf("KDC: Failed to decrypt enrollment request with JOSE: %v", err2)
			var hpkeErrMsg string
			if hpkeDecryptErr != nil {
				hpkeErrMsg = hpkeDecryptErr.Error()
			} else {
				hpkeErrMsg = "HPKE keys not configured"
			}
			return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to decrypt enrollment request (tried HPKE and JOSE): HPKE error: %s, JOSE error: %v", hpkeErrMsg, err2), "", nil, kdcHpkeKeys)
		}
		encryptionBackend = "jose"
		log.Printf("KDC: Successfully decrypted enrollment request using JOSE (decrypted length: %d)", len(decryptedData))
	}

	// 5. Parse decrypted enrollment request JSON
	var enrollmentReq EnrollmentRequest
	if err := json.Unmarshal(decryptedData, &enrollmentReq); err != nil {
		log.Printf("KDC: Failed to parse enrollment request JSON: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to parse enrollment request JSON: %v", err), "", nil, kdcHpkeKeys)
	}

	// 6. Extract pubkeys from request (needed for error responses and validation)
	var hpkePubKey []byte
	var josePubKeyBytes []byte
	if enrollmentReq.HpkePubKey != "" {
		var err error
		hpkePubKey, err = hex.DecodeString(enrollmentReq.HpkePubKey)
		if err != nil || len(hpkePubKey) != 32 {
			// Invalid HPKE pubkey, but we'll handle that in validation step
			hpkePubKey = nil
		}
	}
	if enrollmentReq.JosePubKey != "" {
		josePubKeyBytes = []byte(enrollmentReq.JosePubKey)
	}

	// 7. Validate token
	token, err := kdcDB.ValidateEnrollmentToken(enrollmentReq.AuthToken)
	if err != nil {
		log.Printf("KDC: Enrollment token validation failed: %v", err)
		return returnError(dns.RcodeRefused, fmt.Sprintf("Enrollment token validation failed: %v", err), "", hpkePubKey, kdcHpkeKeys)
	}

	// 8. Validate timestamp (within configured window, default 5 minutes)
	reqTimestamp, err := time.Parse(time.RFC3339, enrollmentReq.Timestamp)
	if err != nil {
		log.Printf("KDC: Invalid timestamp format: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Invalid timestamp format: %v", err), token.NodeID, hpkePubKey, kdcHpkeKeys)
	}

	now := time.Now()
	window := kdcConf.GetEnrollmentExpirationWindow()
	if now.Sub(reqTimestamp) > window || reqTimestamp.Sub(now) > window {
		log.Printf("KDC: Enrollment request timestamp too old or too far in future: %s (window: %v)", enrollmentReq.Timestamp, window)
		return returnError(dns.RcodeRefused, fmt.Sprintf("Enrollment request timestamp out of range (must be within %v): %s", window, enrollmentReq.Timestamp), token.NodeID, hpkePubKey, kdcHpkeKeys)
	}

	// 9. Validate keys - at least one crypto backend must be provided
	if enrollmentReq.HpkePubKey == "" && enrollmentReq.JosePubKey == "" {
		log.Printf("KDC: At least one crypto backend public key (hpke or jose) is required")
		return returnError(dns.RcodeFormatError, "At least one crypto backend public key (hpke or jose) is required", token.NodeID, nil, kdcHpkeKeys)
	}

	// Validate HPKE pubkey if provided
	if enrollmentReq.HpkePubKey != "" {
		if hpkePubKey == nil || len(hpkePubKey) != 32 {
			log.Printf("KDC: Invalid HPKE public key format (length: %d)", len(hpkePubKey))
			return returnError(dns.RcodeFormatError, "Invalid HPKE public key format (must be 32 bytes hex encoded)", token.NodeID, nil, kdcHpkeKeys)
		}
	}

	// Validate JOSE pubkey if provided
	if enrollmentReq.JosePubKey != "" {
		// Get JOSE backend to validate the public key structure and curve
		joseBackend, err := crypto.GetBackend("jose")
		if err != nil {
			log.Printf("KDC: Failed to get JOSE backend for validation: %v", err)
			return returnError(dns.RcodeServerFailure, "Failed to validate JOSE public key (backend unavailable)", token.NodeID, hpkePubKey, kdcHpkeKeys)
		}
		// Parse and validate the JOSE public key (validates JWK structure and supported curves)
		_, err = joseBackend.ParsePublicKey(josePubKeyBytes)
		if err != nil {
			log.Printf("KDC: Invalid JOSE public key (invalid JWK or unsupported curve): %v", err)
			return returnError(dns.RcodeFormatError, "Invalid JOSE public key (invalid JWK or unsupported curve)", token.NodeID, hpkePubKey, kdcHpkeKeys)
		}
	}

	// SIG(0) pubkey: validate DNSKEY format (basic check)
	if enrollmentReq.Sig0PubKey == "" {
		log.Printf("KDC: SIG(0) public key is required")
		return returnError(dns.RcodeFormatError, "SIG(0) public key is required", token.NodeID, hpkePubKey, kdcHpkeKeys)
	}

	// Determine supported crypto backends based on provided keys
	var supportedCrypto []string
	if enrollmentReq.HpkePubKey != "" {
		supportedCrypto = append(supportedCrypto, "hpke")
	}
	if enrollmentReq.JosePubKey != "" {
		supportedCrypto = append(supportedCrypto, "jose")
	}
	if len(supportedCrypto) == 2 {
		log.Printf("KDC: Node supports both HPKE and JOSE crypto backends")
	} else if len(supportedCrypto) == 1 {
		log.Printf("KDC: Node supports %s crypto backend only", supportedCrypto[0])
	}

	// 10. Store node with appropriate pubkey(s)
	nodeID := token.NodeID

	// For JOSE-only nodes, set LongTermPubKey to nil (database allows NULL)
	// The SupportedCrypto field indicates which crypto backends the node supports
	var nodeLongTermPubKey []byte
	if len(hpkePubKey) > 0 {
		nodeLongTermPubKey = hpkePubKey
	} else {
		// JOSE-only node: set to nil (database allows NULL)
		// The SupportedCrypto field will indicate this is a JOSE-only node
		nodeLongTermPubKey = nil
		log.Printf("KDC: Node only supports JOSE - setting LongTermPubKey to NULL")
	}

	// Store JOSE public key if provided
	var nodeLongTermJosePubKey []byte
	if enrollmentReq.JosePubKey != "" {
		nodeLongTermJosePubKey = josePubKeyBytes
		log.Printf("KDC: Storing JOSE public key for node %s (%d bytes)", nodeID, len(nodeLongTermJosePubKey))
	}

	node := &Node{
		ID:                 nodeID,
		Name:               nodeID, // Use node ID as name initially
		LongTermHpkePubKey: nodeLongTermPubKey,
		LongTermJosePubKey: nodeLongTermJosePubKey,
		SupportedCrypto:    supportedCrypto,
		Sig0PubKey:         enrollmentReq.Sig0PubKey,
		NotifyAddress:      enrollmentReq.NotifyAddress,
		State:              NodeStateOnline,
		Comment:            "Enrollment registered",
	}

	// Add node with both pubkeys
	if err := kdcDB.AddNode(node); err != nil {
		log.Printf("KDC: Failed to add node: %v", err)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to add node to database: %v", err), nodeID, hpkePubKey, kdcHpkeKeys)
	}

	// 11. Mark token as used
	// This must succeed to maintain database consistency (node created but token reusable is invalid)
	if err := kdcDB.MarkEnrollmentTokenUsed(enrollmentReq.AuthToken); err != nil {
		log.Printf("KDC: Failed to mark token as used: %v", err)
		// Rollback: delete the node to maintain consistency
		// Node was created but token marking failed - this leaves DB in inconsistent state
		if deleteErr := kdcDB.DeleteNode(nodeID); deleteErr != nil {
			log.Printf("KDC: Critical: Failed to rollback node creation after token marking failure: %v (node %s may be orphaned)", deleteErr, nodeID)
			return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to mark enrollment token as used and rollback failed: token error: %v, rollback error: %v", err, deleteErr), nodeID, hpkePubKey, kdcHpkeKeys)
		}
		log.Printf("KDC: Rolled back node creation for %s after token marking failure", nodeID)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to mark enrollment token as used: %v (node creation rolled back)", err), nodeID, hpkePubKey, kdcHpkeKeys)
	}

	log.Printf("KDC: Enrollment successful for node %s", nodeID)

	// 12. Generate enrollment confirmation
	// Create confirmation JSON
	confirmation := edns0.EnrollmentConfirmation{
		NodeID:    nodeID,
		Status:    "success",
		Timestamp: time.Now().Format(time.RFC3339),
	}
	// Only include HPKE public key if available
	if kdcHpkeKeys != nil {
		confirmation.KdcHpkePubKey = hex.EncodeToString(kdcHpkeKeys.PublicKey)
	}

	confirmationJSON, err := json.Marshal(confirmation)
	if err != nil {
		log.Printf("KDC: Failed to marshal enrollment confirmation: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Encrypt confirmation using the backend that the node actually supports
	// (not necessarily the same as what was used to encrypt the request)
	// Prefer HPKE if node supports it, otherwise use JOSE
	var encryptedConfirmation []byte
	confirmationBackend := ""
	if len(supportedCrypto) > 0 {
		// Use the first supported backend (prefer HPKE if both available)
		for _, backend := range supportedCrypto {
			if backend == "hpke" {
				confirmationBackend = "hpke"
				break
			}
		}
		if confirmationBackend == "" && len(supportedCrypto) > 0 {
			confirmationBackend = supportedCrypto[0]
		}
	}

	if confirmationBackend == "hpke" {
		// Encrypt using HPKE Auth mode
		// KDC's private key (sender authentication), node's HPKE public key (recipient encryption)
		if kdcHpkeKeys == nil {
			log.Printf("KDC: Error: HPKE backend selected but kdcHpkeKeys is nil")
			m.SetRcode(r, dns.RcodeServerFailure)
			return w.WriteMsg(m)
		}
		if len(hpkePubKey) == 0 {
			log.Printf("KDC: Error: Node does not have HPKE public key but HPKE backend was selected")
			m.SetRcode(r, dns.RcodeServerFailure)
			return w.WriteMsg(m)
		}
		encryptedConfirmation, err = hpke.EncryptAuth(kdcHpkeKeys.PrivateKey, hpkePubKey, confirmationJSON)
		if err != nil {
			log.Printf("KDC: Failed to encrypt enrollment confirmation with HPKE: %v", err)
			m.SetRcode(r, dns.RcodeServerFailure)
			return w.WriteMsg(m)
		}
		log.Printf("KDC: Encrypted enrollment confirmation using HPKE")
	} else if confirmationBackend == "jose" {
		// Encrypt using JOSE
		joseBackend, err2 := crypto.GetBackend("jose")
		if err2 != nil {
			log.Printf("KDC: Failed to get JOSE backend for confirmation encryption: %v", err2)
			m.SetRcode(r, dns.RcodeServerFailure)
			return w.WriteMsg(m)
		}
		// Parse node's JOSE public key
		nodeJosePubKey, err2 := joseBackend.ParsePublicKey(josePubKeyBytes)
		if err2 != nil {
			log.Printf("KDC: Failed to parse node JOSE public key: %v", err2)
			m.SetRcode(r, dns.RcodeServerFailure)
			return w.WriteMsg(m)
		}
		encryptedConfirmation, err = joseBackend.Encrypt(nodeJosePubKey, confirmationJSON)
		if err != nil {
			log.Printf("KDC: Failed to encrypt enrollment confirmation with JOSE: %v", err)
			m.SetRcode(r, dns.RcodeServerFailure)
			return w.WriteMsg(m)
		}
		log.Printf("KDC: Encrypted enrollment confirmation using JOSE")
	} else {
		log.Printf("KDC: Error: No supported crypto backend found for confirmation encryption (supported: %v)", supportedCrypto)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Create CHUNK EDNS(0) option with enrollment confirmation
	chunkOpt, err := edns0.CreateEnrollmentConfirmationOption(encryptedConfirmation)
	if err != nil {
		log.Printf("KDC: Failed to create enrollment confirmation option: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Add CHUNK option to response message
	if err := edns0.AddChunkOptionToMessage(m, chunkOpt); err != nil {
		log.Printf("KDC: Failed to add enrollment confirmation option to message: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	log.Printf("KDC: Enrollment confirmation generated and attached to response")

	m.SetRcode(r, dns.RcodeSuccess)
	return w.WriteMsg(m)
}
