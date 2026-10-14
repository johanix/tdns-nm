/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Enrollment blob generation and management
 */

package kdc

import (
	"context"
	"encoding/base64"
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
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// EnrollmentBlob represents the enrollment blob structure
type EnrollmentBlob struct {
	Token                string `json:"token"`                  // Enrollment token value
	NodeID               string `json:"node_id"`                // Node ID
	KdcJosePubKey        string `json:"kdc_jose_pubkey"`        // KDC JOSE public key (JWK JSON, base64 encoded for transport)
	KdcEnrollmentAddress string `json:"kdc_enrollment_address"` // KDC enrollment address (IP:port)
	ControlZone          string `json:"control_zone"`           // Control zone name
}

// GenerateEnrollmentBlobContent generates the enrollment blob content (base64-encoded JSON)
// nodeID: The node ID
// token: The enrollment token
// kdcConf: KDC configuration
// cryptoBackend: Optional crypto backend ("jose"). If empty, JOSE is used.
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
	if cryptoBackend != "" && cryptoBackend != "jose" {
		return "", fmt.Errorf("invalid crypto backend: %s (must be 'jose')", cryptoBackend)
	}

	// Get KDC JOSE public key
	kdcJosePubKeyBytes, err := GetKdcJosePubKey(kdcConf.KdcJosePrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to get KDC JOSE public key: %v", err)
	}
	// JOSE public key is already JWK JSON, base64-encode it for JSON transport
	kdcJosePubKeyB64 := base64.StdEncoding.EncodeToString(kdcJosePubKeyBytes)

	// Create enrollment blob structure
	blob := EnrollmentBlob{
		Token:                token.TokenValue,
		NodeID:               nodeID,
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

	// Generate blob content
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

	// Helper function to return error with CHUNK option containing error details.
	// Error confirmations are sent unencrypted (error messages aren't sensitive).
	// nodeID can be empty if we don't know it yet
	returnError := func(rcode int, errorMsg string, nodeID string) error {
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

		chunkOpt, err := edns0.CreateEnrollmentConfirmationOption(errorJSON)
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

	// 1. Check if UPDATE section has exactly one CHUNK record
	if len(r.Ns) != 1 {
		log.Printf("KDC: Enrollment UPDATE must have exactly one RR in update section, got %d", len(r.Ns))
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Enrollment UPDATE must have exactly one RR in update section, got %d", len(r.Ns)), "")
	}

	// 2. Extract CHUNK record
	rr := r.Ns[0]
	if rr.Header().Rrtype != core.TypeCHUNK {
		log.Printf("KDC: Enrollment UPDATE must contain CHUNK record, got %s", dns.TypeToString[rr.Header().Rrtype])
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Enrollment UPDATE must contain CHUNK record, got %s", dns.TypeToString[rr.Header().Rrtype]), "")
	}

	// Check name pattern: should be _enroll.{control_zone}
	updateName := rr.Header().Name
	if !strings.HasPrefix(updateName, "_enroll.") {
		log.Printf("KDC: Enrollment UPDATE name must start with '_enroll.', got %s", updateName)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Enrollment UPDATE name must start with '_enroll.', got %s", updateName), "")
	}

	// Extract CHUNK data
	chunkRR, ok := rr.(*dns.PrivateRR)
	if !ok {
		log.Printf("KDC: Failed to cast RR to PrivateRR")
		return returnError(dns.RcodeFormatError, "Failed to parse CHUNK record", "")
	}

	chunk, ok := chunkRR.Data.(*core.CHUNK)
	if !ok {
		log.Printf("KDC: Failed to cast CHUNK data")
		return returnError(dns.RcodeFormatError, "Failed to parse CHUNK data", "")
	}

	// Validate CHUNK format: Sequence=0 (enrollment manifest), HMACLen=0
	// Note: Total can be 0 (enrollment with no data chunks) or >0 (enrollment with data chunks)
	if chunk.Sequence != 0 || chunk.HMACLen != 0 {
		log.Printf("KDC: Invalid CHUNK format for enrollment: Sequence=%d, HMACLen=%d", chunk.Sequence, chunk.HMACLen)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Invalid CHUNK format for enrollment: Sequence=%d, HMACLen=%d (Sequence must be 0, HMACLen must be 0)", chunk.Sequence, chunk.HMACLen), "")
	}

	// 3. Extract encrypted enrollment request from CHUNK data
	encryptedData := chunk.Data
	if len(encryptedData) == 0 {
		log.Printf("KDC: CHUNK data is empty")
		return returnError(dns.RcodeFormatError, "CHUNK data is empty", "")
	}

	// 4. Decrypt enrollment request with the KDC JOSE key
	// NOTE: no sender auth required for enrollment; the token authenticates the node
	kdcJoseKeys, err := GetKdcJoseKeypair(kdcConf.KdcJosePrivKey)
	if err != nil {
		log.Printf("KDC: Failed to get KDC JOSE keypair: %v", err)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to decrypt enrollment request: JOSE keypair error: %v", err), "")
	}
	joseBackend, err := crypto.GetBackend("jose")
	if err != nil {
		log.Printf("KDC: Failed to get JOSE backend: %v", err)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to decrypt enrollment request: JOSE backend error: %v", err), "")
	}
	decryptedData, err := joseBackend.Decrypt(kdcJoseKeys.PrivateKey, encryptedData)
	if err != nil {
		log.Printf("KDC: Failed to decrypt enrollment request with JOSE: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to decrypt enrollment request: %v", err), "")
	}
	log.Printf("KDC: Successfully decrypted enrollment request using JOSE (decrypted length: %d)", len(decryptedData))

	// 5. Parse decrypted enrollment request JSON
	var enrollmentReq EnrollmentRequest
	if err := json.Unmarshal(decryptedData, &enrollmentReq); err != nil {
		log.Printf("KDC: Failed to parse enrollment request JSON: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Failed to parse enrollment request JSON: %v", err), "")
	}

	// 6. Extract the node's JOSE public key from the request
	josePubKeyBytes := []byte(enrollmentReq.JosePubKey)

	// 7. Validate token
	token, err := kdcDB.ValidateEnrollmentToken(enrollmentReq.AuthToken)
	if err != nil {
		log.Printf("KDC: Enrollment token validation failed: %v", err)
		return returnError(dns.RcodeRefused, fmt.Sprintf("Enrollment token validation failed: %v", err), "")
	}

	// 8. Validate timestamp (within configured window, default 5 minutes)
	reqTimestamp, err := time.Parse(time.RFC3339, enrollmentReq.Timestamp)
	if err != nil {
		log.Printf("KDC: Invalid timestamp format: %v", err)
		return returnError(dns.RcodeFormatError, fmt.Sprintf("Invalid timestamp format: %v", err), token.NodeID)
	}

	now := time.Now()
	window := kdcConf.GetEnrollmentExpirationWindow()
	if now.Sub(reqTimestamp) > window || reqTimestamp.Sub(now) > window {
		log.Printf("KDC: Enrollment request timestamp too old or too far in future: %s (window: %v)", enrollmentReq.Timestamp, window)
		return returnError(dns.RcodeRefused, fmt.Sprintf("Enrollment request timestamp out of range (must be within %v): %s", window, enrollmentReq.Timestamp), token.NodeID)
	}

	// 9. Validate the JOSE public key (required)
	if enrollmentReq.JosePubKey == "" {
		log.Printf("KDC: JOSE public key is required")
		return returnError(dns.RcodeFormatError, "JOSE public key is required", token.NodeID)
	}
	// Parse and validate the JOSE public key (validates JWK structure and supported curves)
	nodeJosePubKey, err := joseBackend.ParsePublicKey(josePubKeyBytes)
	if err != nil {
		log.Printf("KDC: Invalid JOSE public key (invalid JWK or unsupported curve): %v", err)
		return returnError(dns.RcodeFormatError, "Invalid JOSE public key (invalid JWK or unsupported curve)", token.NodeID)
	}

	// SIG(0) pubkey: validate DNSKEY format (basic check)
	if enrollmentReq.Sig0PubKey == "" {
		log.Printf("KDC: SIG(0) public key is required")
		return returnError(dns.RcodeFormatError, "SIG(0) public key is required", token.NodeID)
	}

	// 10. Store node with its JOSE public key
	nodeID := token.NodeID
	supportedCrypto := []string{"jose"}
	log.Printf("KDC: Storing JOSE public key for node %s (%d bytes)", nodeID, len(josePubKeyBytes))

	node := &Node{
		ID:                 nodeID,
		Name:               nodeID, // Use node ID as name initially
		LongTermJosePubKey: josePubKeyBytes,
		SupportedCrypto:    supportedCrypto,
		Sig0PubKey:         enrollmentReq.Sig0PubKey,
		NotifyAddress:      enrollmentReq.NotifyAddress,
		State:              NodeStateOnline,
		Comment:            "Enrollment registered",
	}

	// Add node
	if err := kdcDB.AddNode(node); err != nil {
		log.Printf("KDC: Failed to add node: %v", err)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to add node to database: %v", err), nodeID)
	}

	// 11. Mark token as used
	// This must succeed to maintain database consistency (node created but token reusable is invalid)
	if err := kdcDB.MarkEnrollmentTokenUsed(enrollmentReq.AuthToken); err != nil {
		log.Printf("KDC: Failed to mark token as used: %v", err)
		// Rollback: delete the node to maintain consistency
		// Node was created but token marking failed - this leaves DB in inconsistent state
		if deleteErr := kdcDB.DeleteNode(nodeID); deleteErr != nil {
			log.Printf("KDC: Critical: Failed to rollback node creation after token marking failure: %v (node %s may be orphaned)", deleteErr, nodeID)
			return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to mark enrollment token as used and rollback failed: token error: %v, rollback error: %v", err, deleteErr), nodeID)
		}
		log.Printf("KDC: Rolled back node creation for %s after token marking failure", nodeID)
		return returnError(dns.RcodeServerFailure, fmt.Sprintf("Failed to mark enrollment token as used: %v (node creation rolled back)", err), nodeID)
	}

	log.Printf("KDC: Enrollment successful for node %s", nodeID)

	// 12. Generate enrollment confirmation
	// Create confirmation JSON
	confirmation := edns0.EnrollmentConfirmation{
		NodeID:    nodeID,
		Status:    "success",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	confirmationJSON, err := json.Marshal(confirmation)
	if err != nil {
		log.Printf("KDC: Failed to marshal enrollment confirmation: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Encrypt confirmation to the node's JOSE public key
	encryptedConfirmation, err := joseBackend.Encrypt(nodeJosePubKey, confirmationJSON)
	if err != nil {
		log.Printf("KDC: Failed to encrypt enrollment confirmation with JOSE: %v", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}
	log.Printf("KDC: Encrypted enrollment confirmation using JOSE")

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
