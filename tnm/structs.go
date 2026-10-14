/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared data structures for tdns-nm (KDC and KRS)
 */

package tnm

// DistributionEntry represents a single operation entry in a distribution
// This is the JSON structure used for encrypted payloads between KDC and KRS
type DistributionEntry struct {
	Operation string `json:"operation"` // "ping", "roll_key", "delete_key", "node_components"

	// Key-specific fields (for roll_key, delete_key)
	ZoneName   string `json:"zone_name,omitempty"`
	KeyID      string `json:"key_id,omitempty"`
	KeyType    string `json:"key_type,omitempty"`    // "KSK", "ZSK", "CSK"
	Algorithm  uint8  `json:"algorithm,omitempty"`   // DNSSEC algorithm number
	Flags      uint16 `json:"flags,omitempty"`       // DNSSEC flags (256 for ZSK, 257 for KSK)
	PublicKey  string `json:"public_key,omitempty"`  // Public key in DNSKEY RR format
	PrivateKey string `json:"private_key,omitempty"` // Base64-encoded private key (for roll_key only)

	// Operation-specific metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}
