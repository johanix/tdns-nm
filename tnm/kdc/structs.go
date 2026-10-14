/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Data structures for tdns-kdc (Key Distribution Center)
 */

package kdc

import (
	"time"
)

// ZoneSigningMode represents how a zone is signed
type ZoneSigningMode string

const (
	ZoneSigningModeUpstream     ZoneSigningMode = "upstream"      // Upstream signed, no keys distributed
	ZoneSigningModeCentral      ZoneSigningMode = "central"       // Centrally signed, no keys distributed (default)
	ZoneSigningModeEdgesignDyn  ZoneSigningMode = "edgesign_dyn"  // ZSK distributed, signs dynamic responses only
	ZoneSigningModeEdgesignZsk  ZoneSigningMode = "edgesign_zsk"  // ZSK distributed, signs all responses
	ZoneSigningModeEdgesignFull ZoneSigningMode = "edgesign_full" // KSK+ZSK distributed, all signing at edge
	ZoneSigningModeUnsigned     ZoneSigningMode = "unsigned"      // No DNSSEC signing
)

// Zone represents a DNS zone managed by the KDC
// Note: Signing mode is derived from component assignment, not stored directly
type Zone struct {
	Name      string    `json:"name"`       // Zone name (e.g., "example.com.") - used as primary key
	ServiceID string    `json:"service_id"` // Service this zone belongs to
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Active    bool      `json:"active"`  // Whether the zone is actively managed
	Comment   string    `json:"comment"` // Optional comment/description
}

// Service represents a logical service that groups zones
type Service struct {
	ID        string    `json:"id"`   // Unique identifier (e.g., "customer-service")
	Name      string    `json:"name"` // Human-readable name
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Active    bool      `json:"active"`  // Whether the service is active
	Comment   string    `json:"comment"` // Optional comment/description
}

// Component represents a component within a service
// Components can serve both signed and unsigned zones
type Component struct {
	ID        string    `json:"id"`   // Unique identifier (e.g., "web-component")
	Name      string    `json:"name"` // Human-readable name
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Active    bool      `json:"active"`  // Whether the component is active
	Comment   string    `json:"comment"` // Optional comment/description
}

// ServiceComponentAssignment represents which components belong to which services
type ServiceComponentAssignment struct {
	ServiceID   string    `json:"service_id"`
	ComponentID string    `json:"component_id"`
	Active      bool      `json:"active"` // Whether this assignment is active
	Since       time.Time `json:"since"`
}

// ComponentZoneAssignment represents which zones are served by which components
type ComponentZoneAssignment struct {
	ComponentID string    `json:"component_id"`
	ZoneName    string    `json:"zone_name"`
	Active      bool      `json:"active"` // Whether this assignment is active
	Since       time.Time `json:"since"`
}

// NodeComponentAssignment represents which components are served by which nodes
type NodeComponentAssignment struct {
	NodeID      string    `json:"node_id"`
	ComponentID string    `json:"component_id"`
	Active      bool      `json:"active"` // Whether this assignment is active
	Since       time.Time `json:"since"`
}

// NodeState represents the state of an edge node
type NodeState string

const (
	NodeStateOnline      NodeState = "online"
	NodeStateOffline     NodeState = "offline"
	NodeStateCompromised NodeState = "compromised"
	NodeStateSuspended   NodeState = "suspended"
)

// Node represents an edge server that receives ZSK keys
type Node struct {
	ID                 string     `json:"id"`                               // Unique identifier for the node
	Name               string     `json:"name"`                             // Human-readable name
	LongTermHpkePubKey []byte     `json:"long_term_hpke_pub_key"`           // HPKE long-term public key (32 bytes, X25519)
	LongTermJosePubKey []byte     `json:"long_term_jose_pub_key,omitempty"` // JOSE long-term public key (JWK JSON bytes)
	SupportedCrypto    []string   `json:"supported_crypto,omitempty"`       // List of supported crypto backends (e.g., ["hpke", "jose"])
	Sig0PubKey         string     `json:"sig0_pub_key,omitempty"`           // SIG(0) public key (DNSKEY RR format string)
	NotifyAddress      string     `json:"notify_address"`                   // Address:port for sending NOTIFY messages (e.g., "192.0.2.1:53")
	RegisteredAt       time.Time  `json:"registered_at"`
	LastSeen           time.Time  `json:"last_seen"`
	LastContact        *time.Time `json:"last_contact,omitempty"` // Most recent confirmation of successful operation
	State              NodeState  `json:"state"`
	Comment            string     `json:"comment"` // Optional comment/description
	Zones              []string   `json:"zones"`   // List of zone names this node serves (for future use)
}

// EnrollmentToken represents an enrollment token for node registration
type EnrollmentToken struct {
	TokenID     string     `json:"token_id"`               // Unique token identifier
	TokenValue  string     `json:"token_value"`            // Token value (cryptographically random)
	NodeID      string     `json:"node_id"`                // Assigned node ID
	CreatedAt   time.Time  `json:"created_at"`             // When token was created
	ActivatedAt *time.Time `json:"activated_at,omitempty"` // When token was activated (nil until activated)
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`   // When token expires (nil until activated)
	Activated   bool       `json:"activated"`              // Whether token is activated
	Used        bool       `json:"used"`                   // Whether token has been used
	UsedAt      *time.Time `json:"used_at,omitempty"`      // When token was used (nil until used)
	CreatedBy   string     `json:"created_by,omitempty"`   // Admin user/identifier
	Comment     string     `json:"comment,omitempty"`      // Optional comment
}

// KeyType represents the type of DNSSEC key
type KeyType string

const (
	KeyTypeKSK KeyType = "KSK"
	KeyTypeZSK KeyType = "ZSK"
	KeyTypeCSK KeyType = "CSK"
)

// OperationType represents the type of distribution operation
type OperationType string

const (
	OperationPing           OperationType = "ping"            // Health check / nonce challenge-response
	OperationRollKey        OperationType = "roll_key"        // Add new key (initial distribution or rollover)
	OperationDeleteKey      OperationType = "delete_key"      // Remove key from node
	OperationNodeComponents OperationType = "node_components" // Update node's component subscriptions
)

// KeyState represents the state of a DNSSEC key in the KDC
type KeyState string

const (
	KeyStateCreated     KeyState = "created"
	KeyStatePublished   KeyState = "published"
	KeyStateStandby     KeyState = "standby"
	KeyStateActive      KeyState = "active"      // Active but not distributed (central signer) - for KSKs: "active:C"
	KeyStateActiveDist  KeyState = "active_dist" // Active and being distributed (for KSKs: "active:C+dist", for ZSKs: same as "distributed")
	KeyStateActiveCE    KeyState = "active_ce"   // Active both central and at edges (for KSKs: "active:CE", final state after all confirmations)
	KeyStateDistributed KeyState = "distributed" // Currently being distributed to nodes (for ZSKs)
	KeyStateEdgeSigner  KeyState = "edgesigner"  // Active on edge nodes (for ZSKs, final state after all confirmations)
	KeyStateRetired     KeyState = "retired"
	KeyStateRemoved     KeyState = "removed"
	KeyStateRevoked     KeyState = "revoked"
)

// IsActiveKeyState returns true if the key state represents an active key
// KeyStateActive, KeyStateActiveDist, and KeyStateActiveCE all qualify as "active"
func IsActiveKeyState(state KeyState) bool {
	return state == KeyStateActive || state == KeyStateActiveDist || state == KeyStateActiveCE
}

// DNSSECKey represents a DNSSEC key (KSK, ZSK, or CSK) for a zone
type DNSSECKey struct {
	ID          string     `json:"id"`         // Unique identifier
	ZoneName    string     `json:"zone_name"`  // Zone name this key belongs to
	KeyType     KeyType    `json:"key_type"`   // KSK, ZSK, or CSK
	KeyID       uint16     `json:"key_id"`     // DNSSEC KeyTag
	Algorithm   uint8      `json:"algorithm"`  // DNSSEC algorithm (e.g., 13 for ECDSA256, 15 for ED25519)
	Flags       uint16     `json:"flags"`      // DNSSEC flags (257 for KSK/CSK, 256 for ZSK)
	PublicKey   string     `json:"public_key"` // Public key RR string (DNSKEY record)
	PrivateKey  []byte     `json:"-"`          // Private key (never sent in API responses)
	State       KeyState   `json:"state"`      // Current state of the key
	CreatedAt   time.Time  `json:"created_at"`
	PublishedAt *time.Time `json:"published_at,omitempty"` // When the key was published
	ActivatedAt *time.Time `json:"activated_at,omitempty"` // When the key was activated
	RetiredAt   *time.Time `json:"retired_at,omitempty"`   // When the key was retired
	Comment     string     `json:"comment"`                // Optional comment
}

// DistributionStatus is the lifecycle status of a distribution record.
// Moved here from tdns-transport v2/hpke/types.go, which dropped it in
// f32e048 (cleanup step 7); only the KDC uses it.
type DistributionStatus string

const (
	DistributionStatusPending   DistributionStatus = "pending"
	DistributionStatusDelivered DistributionStatus = "delivered"
	DistributionStatusActive    DistributionStatus = "active"
	DistributionStatusRevoked   DistributionStatus = "revoked"
)

// DistributionRecord represents a record of a key distribution to a node
type DistributionRecord struct {
	ID              string // Unique ID for this distribution
	ZoneName        string // Zone name (NULL for non-key operations like ping, update_components)
	KeyID           string // DNSSEC key ID (NULL for non-key operations)
	NodeID          string // Target node ID (empty if to all nodes)
	EncryptedKey    []byte // HPKE-encrypted private key (NULL for unencrypted operations like delete_key)
	EphemeralPubKey []byte // Ephemeral public key used for encryption (NULL for unencrypted operations).
	// For HPKE: 32-byte X25519 ephemeral public key (extracted from ciphertext).
	// For JOSE: Empty (ephemeral key is embedded in JWE header within ciphertext).
	CreatedAt      time.Time
	ExpiresAt      *time.Time // Optional expiration of the distributed key
	Status         DistributionStatus
	DistributionID string                 // HPKE distribution ID (for tracking)
	CompletedAt    *time.Time             // When distribution was completed (nil if not completed)
	Operation      string                 // Operation type: ping, roll_key, delete_key, node_components
	Payload        map[string]interface{} `json:"payload,omitempty"` // Operation-specific metadata (JSON)
}

// DistributionSummaryInfo represents summary information about a distribution for listing
type DistributionSummaryInfo struct {
	DistributionID string            `json:"distribution_id"`
	Nodes          []string          `json:"nodes"`        // Nodes this distribution applies to
	Zones          []string          `json:"zones"`        // Zones in this distribution
	ContentType    string            `json:"content_type"` // node_operations, key_operations, mgmt_operations, or mixed_operations
	Operations     []string          `json:"operations"`   // List of operation types (e.g., "ping", "roll_key", "delete_key", "update_components")
	ZSKCount       int               `json:"zsk_count"`    // Number of ZSK keys
	KSKCount       int               `json:"ksk_count"`    // Number of KSK keys
	Keys           map[string]string `json:"keys"`         // Map of zone -> key_id (for verbose mode)
	CreatedAt      string            `json:"created_at"`
	CompletedAt    *string           `json:"completed_at,omitempty"`
	AllConfirmed   bool              `json:"all_confirmed"`
	ConfirmedNodes []string          `json:"confirmed_nodes,omitempty"` // Nodes that have confirmed
	PendingNodes   []string          `json:"pending_nodes,omitempty"`   // Nodes that haven't confirmed yet
}

// ZoneNodeAssignment is deprecated - use Component-based model instead
// Kept for backward compatibility during migration
type ZoneNodeAssignment struct {
	ZoneName string
	NodeID   string
	Active   bool // Whether this assignment is active
	Since    time.Time
}

// ServiceTransactionState represents the state of a service modification transaction
type ServiceTransactionState string

const (
	ServiceTransactionStateOpen       ServiceTransactionState = "open"
	ServiceTransactionStateCommitted  ServiceTransactionState = "committed"
	ServiceTransactionStateRolledBack ServiceTransactionState = "rolled_back"
)

// ServiceTransactionChanges represents pending changes in a transaction
type ServiceTransactionChanges struct {
	AddComponents    []string `json:"add_components"`
	RemoveComponents []string `json:"remove_components"`
}

// ServiceTransaction represents a transaction for modifying a service
type ServiceTransaction struct {
	ID              string                    `json:"id"`         // Transaction token (e.g., "tx1234")
	ServiceID       string                    `json:"service_id"` // Service being modified
	CreatedAt       time.Time                 `json:"created_at"`
	ExpiresAt       time.Time                 `json:"expires_at"`
	State           ServiceTransactionState   `json:"state"`                      // open, committed, rolled_back
	Changes         ServiceTransactionChanges `json:"changes"`                    // Pending changes
	CreatedBy       string                    `json:"created_by,omitempty"`       // Optional: user/process that created it
	Comment         string                    `json:"comment,omitempty"`          // Optional: description
	ServiceSnapshot map[string]interface{}    `json:"service_snapshot,omitempty"` // Snapshot of service state at start (for conflict detection)
}

// DistributionPlan represents a planned key distribution
type DistributionPlan struct {
	ZoneName string   `json:"zone_name"`
	NodeID   string   `json:"node_id"`
	KeyIDs   []string `json:"key_ids"` // Which keys would be distributed
}

// DeltaSummary provides summary statistics about a delta
type DeltaSummary struct {
	TotalZonesAffected    int `json:"total_zones_affected"`
	TotalDistributions    int `json:"total_distributions"`
	TotalNodesAffected    int `json:"total_nodes_affected"`
	ZonesNewlyServed      int `json:"zones_newly_served"`
	ZonesNoLongerServed   int `json:"zones_no_longer_served"`
	DistributionsToCreate int `json:"distributions_to_create"`
	DistributionsToRevoke int `json:"distributions_to_revoke"`
}

// DeltaReport represents the impact analysis of service changes
type DeltaReport struct {
	ServiceID             string              `json:"service_id"`
	TransactionID         string              `json:"transaction_id,omitempty"`
	OriginalComponents    []string            `json:"original_components"`         // Components before transaction
	UpdatedComponents     []string            `json:"updated_components"`          // Components after transaction
	AddedComponents       []string            `json:"added_components"`            // Components being added
	RemovedComponents     []string            `json:"removed_components"`          // Components being removed
	IsValid               bool                `json:"is_valid"`                    // Whether service is valid (has exactly one signing component)
	ValidationErrors      []string            `json:"validation_errors,omitempty"` // Validation error messages
	ZonesNewlyServed      map[string][]string `json:"zones_newly_served"`          // zone -> nodes that will serve it
	ZonesNoLongerServed   map[string][]string `json:"zones_no_longer_served"`      // zone -> nodes that will stop serving it
	DistributionsToCreate []DistributionPlan  `json:"distributions_to_create"`
	DistributionsToRevoke []DistributionPlan  `json:"distributions_to_revoke"`
	Summary               DeltaSummary        `json:"summary"`
}
