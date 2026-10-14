/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * API endpoints for tdns-kdc management
 */

package kdc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	tnm "github.com/johanix/tdns-nm/tnm"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// KdcZonePost represents a request to the KDC zone API
type KdcZonePost struct {
	Command       string   `json:"command"` // "add", "list", "get", "get-keys", "generate-key", "encrypt-key", "update", "delete", "distrib-single", "distrib-multi", "transition", "setstate", "delete-key", "purge-keys", "set-service", "set-component"
	Zone          *Zone    `json:"zone,omitempty"`
	ZoneName      string   `json:"zone_name,omitempty"`      // Zone name (replaces zone_id)
	ServiceID     string   `json:"service_id,omitempty"`     // For set-service command
	ServiceName   string   `json:"service_name,omitempty"`   // For set-service command (CLI convenience)
	ComponentID   string   `json:"component_id,omitempty"`   // For set-component command
	ComponentName string   `json:"component_name,omitempty"` // For set-component command (CLI convenience)
	KeyID         string   `json:"key_id,omitempty"`         // For encrypt-key/distrib-single/transition/setstate/delete-key: DNSSEC key ID
	NodeID        string   `json:"node_id,omitempty"`        // For encrypt-key: node ID
	KeyType       string   `json:"key_type,omitempty"`       // For generate-key: "KSK", "ZSK", or "CSK"
	Algorithm     uint8    `json:"algorithm,omitempty"`      // For generate-key: DNSSEC algorithm
	Comment       string   `json:"comment,omitempty"`        // For generate-key: optional comment
	NewState      string   `json:"new_state,omitempty"`      // For setstate: target state
	Zones         []string `json:"zones,omitempty"`          // For distrib-multi: list of zone names
	Force         bool     `json:"force,omitempty"`          // For purge-keys: also delete distributed keys
	Crypto        string   `json:"crypto,omitempty"`         // For distrib-multi and ping: force crypto backend ("jose")
}

// DistributionResult represents the result of distributing a key for a zone
type DistributionResult struct {
	ZoneName string `json:"zone_name"`
	KeyID    string `json:"key_id,omitempty"`
	Status   string `json:"status"` // "success" or "error"
	Msg      string `json:"msg,omitempty"`
}

// ZoneEnrichment contains additional information about a zone for display
type ZoneEnrichment struct {
	ServiceName        string   `json:"service_name,omitempty"`
	ComponentIDs       []string `json:"component_ids,omitempty"`
	ComponentNames     []string `json:"component_names,omitempty"`
	SigningComponentID string   `json:"signing_component_id,omitempty"` // The sign_* component (for Signing Mode column)
	NodeIDs            []string `json:"node_ids,omitempty"`             // For verbose mode
}

// KdcZoneResponse represents a response from the KDC zone API
type KdcZoneResponse struct {
	Time            time.Time                  `json:"time"`
	Error           bool                       `json:"error,omitempty"`
	ErrorMsg        string                     `json:"error_msg,omitempty"`
	Msg             string                     `json:"msg,omitempty"`
	Zone            *Zone                      `json:"zone,omitempty"`
	Zones           []*Zone                    `json:"zones,omitempty"`
	ZoneEnrichments map[string]*ZoneEnrichment `json:"zone_enrichments,omitempty"` // Keyed by zone name
	Key             *DNSSECKey                 `json:"key,omitempty"`
	Keys            []*DNSSECKey               `json:"keys,omitempty"`
	EncryptedKey    string                     `json:"encrypted_key,omitempty"`     // Base64-encoded
	EphemeralPubKey string                     `json:"ephemeral_pub_key,omitempty"` // Base64-encoded
	DistributionID  string                     `json:"distribution_id,omitempty"`
	Results         []DistributionResult       `json:"results,omitempty"` // For distrib-multi: results per zone
}

// KdcNodePost represents a request to the KDC node API
type KdcNodePost struct {
	Command string `json:"command"` // "add", "list", "get", "update", "delete", "set-state"
	Node    *Node  `json:"node,omitempty"`
	NodeID  string `json:"node_id,omitempty"`
	State   string `json:"state,omitempty"` // For set-state command
}

// KdcNodeResponse represents a response from the KDC node API
type KdcNodeResponse struct {
	Time     time.Time `json:"time"`
	Error    bool      `json:"error,omitempty"`
	ErrorMsg string    `json:"error_msg,omitempty"`
	Msg      string    `json:"msg,omitempty"`
	Node     *Node     `json:"node,omitempty"`
	Nodes    []*Node   `json:"nodes,omitempty"`
}

// KdcServicePost represents a request to the KDC service API
type KdcServicePost struct {
	Command     string   `json:"command"` // "add", "list", "get", "update", "delete"
	Service     *Service `json:"service,omitempty"`
	ServiceID   string   `json:"service_id,omitempty"`
	ServiceName string   `json:"service_name,omitempty"` // For CLI convenience
}

// KdcServiceResponse represents a response from the KDC service API
type KdcServiceResponse struct {
	Time     time.Time  `json:"time"`
	Error    bool       `json:"error,omitempty"`
	ErrorMsg string     `json:"error_msg,omitempty"`
	Msg      string     `json:"msg,omitempty"`
	Service  *Service   `json:"service,omitempty"`
	Services []*Service `json:"services,omitempty"`
}

// KdcComponentPost represents a request to the KDC component API
type KdcComponentPost struct {
	Command       string     `json:"command"` // "add", "list", "get", "update", "delete"
	Component     *Component `json:"component,omitempty"`
	ComponentID   string     `json:"component_id,omitempty"`
	ComponentName string     `json:"component_name,omitempty"` // For CLI convenience
}

// KdcComponentResponse represents a response from the KDC component API
type KdcComponentResponse struct {
	Time       time.Time    `json:"time"`
	Error      bool         `json:"error,omitempty"`
	ErrorMsg   string       `json:"error_msg,omitempty"`
	Msg        string       `json:"msg,omitempty"`
	Component  *Component   `json:"component,omitempty"`
	Components []*Component `json:"components,omitempty"`
}

// KdcServiceComponentPost represents a request for service-component assignment
type KdcServiceComponentPost struct {
	Command          string `json:"command"` // "add", "delete", "list", "replace"
	ServiceID        string `json:"service_id,omitempty"`
	ServiceName      string `json:"service_name,omitempty"` // For CLI convenience
	ComponentID      string `json:"component_id,omitempty"`
	ComponentName    string `json:"component_name,omitempty"`     // For CLI convenience
	OldComponentID   string `json:"old_component_id,omitempty"`   // For replace command
	OldComponentName string `json:"old_component_name,omitempty"` // For replace command
	NewComponentID   string `json:"new_component_id,omitempty"`   // For replace command
	NewComponentName string `json:"new_component_name,omitempty"` // For replace command
}

// KdcServiceComponentResponse represents a response for service-component assignment
type KdcServiceComponentResponse struct {
	Time        time.Time                     `json:"time"`
	Error       bool                          `json:"error,omitempty"`
	ErrorMsg    string                        `json:"error_msg,omitempty"`
	Msg         string                        `json:"msg,omitempty"`
	Assignments []*ServiceComponentAssignment `json:"assignments,omitempty"`
}

// KdcServiceTransactionPost represents a request to the KDC service transaction API
type KdcServiceTransactionPost struct {
	Command       string `json:"command"` // "start", "add-component", "remove-component", "view", "commit", "rollback", "list", "get", "status", "cleanup"
	ServiceID     string `json:"service_id,omitempty"`
	ServiceName   string `json:"service_name,omitempty"` // For CLI convenience
	TxID          string `json:"tx_id,omitempty"`        // Transaction ID
	ComponentID   string `json:"component_id,omitempty"`
	ComponentName string `json:"component_name,omitempty"` // For CLI convenience
	CreatedBy     string `json:"created_by,omitempty"`
	Comment       string `json:"comment,omitempty"`
	DryRun        bool   `json:"dry_run,omitempty"`      // For commit command: if true, don't apply changes
	StateFilter   string `json:"state_filter,omitempty"` // For list command: filter by state
}

// KdcServiceTransactionResponse represents a response from the KDC service transaction API
type KdcServiceTransactionResponse struct {
	Time         time.Time             `json:"time"`
	Error        bool                  `json:"error,omitempty"`
	ErrorMsg     string                `json:"error_msg,omitempty"`
	Msg          string                `json:"msg,omitempty"`
	TxID         string                `json:"tx_id,omitempty"`
	Transaction  *ServiceTransaction   `json:"transaction,omitempty"`
	Transactions []*ServiceTransaction `json:"transactions,omitempty"`
	DeltaReport  *DeltaReport          `json:"delta_report,omitempty"`
}

// KdcNodeComponentPost represents a request for node-component assignment
type KdcNodeComponentPost struct {
	Command       string `json:"command"` // "add", "delete", "list"
	NodeID        string `json:"node_id,omitempty"`
	NodeName      string `json:"node_name,omitempty"` // For CLI convenience
	ComponentID   string `json:"component_id,omitempty"`
	ComponentName string `json:"component_name,omitempty"` // For CLI convenience
}

// KdcNodeComponentResponse represents a response for node-component assignment
type KdcNodeComponentResponse struct {
	Time        time.Time                  `json:"time"`
	Error       bool                       `json:"error,omitempty"`
	ErrorMsg    string                     `json:"error_msg,omitempty"`
	Msg         string                     `json:"msg,omitempty"`
	Assignments []*NodeComponentAssignment `json:"assignments,omitempty"`
}

// sendJSONError sends a JSON-formatted error response
func sendJSONError(w http.ResponseWriter, statusCode int, errorMsg string) {
	resp := map[string]interface{}{
		"time":      time.Now(),
		"error":     true,
		"error_msg": errorMsg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// APIKdcZone handles zone management endpoints
func APIKdcZone(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcZone handler called")
		}
		var req KdcZonePost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcZoneResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Zone == nil {
				sendJSONError(w, http.StatusBadRequest, "zone is required for add command")
				return
			}
			if req.Zone.Name == "" {
				sendJSONError(w, http.StatusBadRequest, "zone name is required")
				return
			}
			if err := kdcDB.AddZone(req.Zone); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s added successfully", req.Zone.Name)
			}

		case "list":
			zones, err := kdcDB.GetAllZones()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Zones = zones
				// Enrich zones with service name and components
				resp.ZoneEnrichments = make(map[string]*ZoneEnrichment)
				for _, zone := range zones {
					enrichment := &ZoneEnrichment{}

					// Get service name
					if zone.ServiceID != "" {
						service, err := kdcDB.GetService(zone.ServiceID)
						if err == nil {
							enrichment.ServiceName = service.Name
						} else {
							enrichment.ServiceName = zone.ServiceID // Fallback to ID
						}
					}

					// Get components for this zone via its service (not direct assignments)
					// Zones are related to services, and components are derived from the service
					if zone.ServiceID != "" {
						componentIDs, err := kdcDB.GetComponentsForService(zone.ServiceID)
						if err == nil {
							// Separate signing components (sign_*) from non-signing components
							var signingComponentID string
							var nonSigningComponents []string

							// First pass: find sign_kdc if it exists
							for _, compID := range componentIDs {
								if compID == "sign_kdc" {
									signingComponentID = compID
									break
								}
							}

							// Second pass: if no sign_kdc, find first sign_* component
							if signingComponentID == "" {
								for _, compID := range componentIDs {
									if strings.HasPrefix(compID, "sign_") {
										signingComponentID = compID
										break
									}
								}
							}

							// Third pass: collect all non-signing components
							for _, compID := range componentIDs {
								if !strings.HasPrefix(compID, "sign_") {
									nonSigningComponents = append(nonSigningComponents, compID)
								}
							}

							// If no sign_* component found, default to sign_kdc
							if signingComponentID == "" {
								signingComponentID = "sign_kdc"
							}

							enrichment.SigningComponentID = signingComponentID
							enrichment.ComponentIDs = nonSigningComponents
							enrichment.ComponentNames = nonSigningComponents

							// Get nodes for components (for verbose mode - we'll include them always)
							nodeSet := make(map[string]bool)
							for _, compID := range componentIDs {
								nodes, err := kdcDB.GetNodesForComponent(compID)
								if err == nil {
									for _, nodeID := range nodes {
										nodeSet[nodeID] = true
									}
								}
							}
							for nodeID := range nodeSet {
								enrichment.NodeIDs = append(enrichment.NodeIDs, nodeID)
							}
						}
					}

					resp.ZoneEnrichments[zone.Name] = enrichment
				}
			}

		case "get":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for get command")
				return
			}
			zone, err := kdcDB.GetZone(req.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Zone = zone
			}

		case "get-keys":
			var keys []*DNSSECKey
			var err error
			if req.ZoneName == "" {
				// List all keys for all zones
				keys, err = kdcDB.GetAllDNSSECKeys()
			} else {
				// List keys for a specific zone
				keys, err = kdcDB.GetDNSSECKeysForZone(req.ZoneName)
			}
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Keys = keys
			}

		case "encrypt-key":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for encrypt-key command")
				return
			}
			keyID := req.KeyID
			nodeID := req.NodeID
			if keyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for encrypt-key command")
				return
			}
			if nodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for encrypt-key command")
				return
			}

			// Get the DNSSEC key by ID
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, keyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// Get the node
				node, err := kdcDB.GetNode(nodeID)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("node %s not found: %v", nodeID, err)
				} else {
					// Encrypt the key
					encryptedKey, ephemeralPubKey, distributionID, err := kdcDB.EncryptKeyForNode(key, node, kdcConf)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = "Key encrypted successfully"
						// Base64 encode binary data for JSON
						resp.EncryptedKey = base64.StdEncoding.EncodeToString(encryptedKey)
						resp.EphemeralPubKey = base64.StdEncoding.EncodeToString(ephemeralPubKey)
						resp.DistributionID = distributionID
					}
				}
			}

		case "generate-key":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for generate-key command")
				return
			}
			// Verify zone exists
			_, err := kdcDB.GetZone(req.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone not found: %v", err)
			} else {
				// Use default algorithm from config if not specified
				algorithm := req.Algorithm
				if algorithm == 0 {
					// TODO: Get from KDC config - for now use ED25519
					algorithm = dns.ED25519
				}
				keyType := KeyType(req.KeyType)
				if keyType == "" {
					keyType = KeyTypeZSK // Default to ZSK
				}
				key, err := kdcDB.GenerateDNSSECKey(req.ZoneName, keyType, algorithm, req.Comment)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Store the key in database
					if err := kdcDB.AddDNSSECKey(key); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Key %s generated successfully", key.ID)
						resp.Key = key
					}
				}
			}

		case "update":
			if req.Zone == nil || req.Zone.Name == "" {
				sendJSONError(w, http.StatusBadRequest, "zone with name is required for update command")
				return
			}
			if err := kdcDB.UpdateZone(req.Zone); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s updated successfully", req.Zone.Name)
			}

		case "set-service":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for set-service command")
				return
			}
			// Get service ID from name if provided
			serviceID := req.ServiceID
			if serviceID == "" && req.ServiceName != "" {
				// Look up service by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to get services: %v", err)
				} else {
					found := false
					for _, s := range services {
						if s.Name == req.ServiceName {
							serviceID = s.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					}
				}
			}
			if serviceID == "" {
				sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for set-service command")
				return
			}
			// Get zone
			zone, err := kdcDB.GetZone(req.ZoneName)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone not found: %v", err)
			} else {
				// Update zone service
				zone.ServiceID = serviceID
				if err := kdcDB.UpdateZone(zone); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Get signing mode from service components (zones derive components from service)
					newSigningMode, err := kdcDB.GetZoneSigningMode(req.ZoneName)
					if err != nil {
						log.Printf("KDC: Warning: Failed to get signing mode for zone %s: %v", req.ZoneName, err)
						newSigningMode = ZoneSigningModeCentral // Default
					}

					// Get components from the service for display
					serviceComponents, err := kdcDB.GetComponentsForService(serviceID)
					if err != nil {
						log.Printf("KDC: Warning: Failed to get components for service %s: %v", serviceID, err)
					}

					componentNames := make([]string, 0, len(serviceComponents))
					for _, compID := range serviceComponents {
						comp, err := kdcDB.GetComponent(compID)
						if err == nil {
							componentNames = append(componentNames, comp.Name)
						} else {
							componentNames = append(componentNames, compID)
						}
					}

					componentsStr := strings.Join(componentNames, ", ")
					if componentsStr == "" {
						componentsStr = "(none)"
					}

					resp.Msg = fmt.Sprintf("Zone %s assigned to service %s (signing mode: %s, components: %s)", req.ZoneName, serviceID, newSigningMode, componentsStr)
					resp.Zone = zone
				}
			}

		case "delete":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for delete command")
				return
			}
			if err := kdcDB.DeleteZone(req.ZoneName); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Zone %s deleted successfully", req.ZoneName)
			}

		case "distrib-single":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for distrib-single command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for distrib-single command")
				return
			}
			// Get the key and verify it's a ZSK in standby state
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key not found: %v", err)
			} else if key.KeyType != KeyTypeZSK {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key %s is not a ZSK (type: %s)", req.KeyID, key.KeyType)
			} else if key.State != KeyStateStandby {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key %s is not in standby state (current state: %s)", req.KeyID, key.State)
			} else {
				// Check if zone uses sign_edge_full and get active KSK
				signingMode, _ := kdcDB.GetZoneSigningMode(req.ZoneName)
				var activeKSK *DNSSECKey
				if signingMode == ZoneSigningModeEdgesignFull {
					keys, _ := kdcDB.GetDNSSECKeysForZone(req.ZoneName)
					for _, k := range keys {
						if k.KeyType == KeyTypeKSK && k.State == KeyStateActive {
							activeKSK = k
							break
						}
					}
				}
				// Get distributionID for this key (before transitioning state)
				distributionID, err := kdcDB.GetOrCreateDistributionID(req.ZoneName, key)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to get/create distribution ID: %v", err)
				} else {
					// Transition to distributed state
					if err := kdcDB.UpdateKeyState(req.ZoneName, req.KeyID, KeyStateDistributed); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						// Check zone signing mode - only distribute keys for edgesigned zones
						_, err := kdcDB.GetZone(req.ZoneName)
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("Failed to get zone: %v", err)
						} else {
							signingMode, err := kdcDB.GetZoneSigningMode(req.ZoneName)
							if err != nil {
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Failed to get signing mode: %v", err)
							} else if signingMode != ZoneSigningModeEdgesignDyn && signingMode != ZoneSigningModeEdgesignZsk && signingMode != ZoneSigningModeEdgesignFull {
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Zone %s has signing_mode=%s, keys are not distributed to nodes (only edgesign_* modes support key distribution)", req.ZoneName, signingMode)
							} else {
								// Get nodes that serve this zone (via components)
								nodes, err := kdcDB.GetActiveNodesForZone(req.ZoneName)
								if err != nil {
									log.Printf("KDC: Warning: Failed to get nodes for zone: %v", err)
								} else if len(nodes) == 0 {
									log.Printf("KDC: Warning: No active nodes serve zone %s", req.ZoneName)
								} else {
									encryptedCount := 0
									for _, node := range nodes {
										if node.NotifyAddress == "" {
											log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
											continue
										}
										// Encrypt key for this node under the announced distribution ID (creates distribution record)
										_, _, _, err := kdcDB.EncryptKeyForNode(key, node, kdcConf, distributionID)
										if err != nil {
											log.Printf("KDC: Warning: Failed to encrypt key for node %s: %v", node.ID, err)
											continue
										}
										encryptedCount++
										log.Printf("KDC: Encrypted key %s for node %s (distribution ID: %s)", req.KeyID, node.ID, distributionID)
									}
									log.Printf("KDC: Encrypted key for %d/%d nodes serving zone %s", encryptedCount, len(nodes), req.ZoneName)
								}

								// Distribute active KSK for edgesign_full zones
								if activeKSK != nil {
									kskDistributionID, err := kdcDB.GetOrCreateDistributionID(req.ZoneName, activeKSK)
									if err != nil {
										log.Printf("KDC: Warning: Failed to get/create distribution ID for KSK %s: %v", activeKSK.ID, err)
									} else {
										// Transition to active_dist state
										if err := kdcDB.UpdateKeyState(req.ZoneName, activeKSK.ID, KeyStateActiveDist); err != nil {
											log.Printf("KDC: Warning: Failed to update KSK state: %v", err)
										} else {
											// Encrypt KSK for all nodes
											kskEncryptedCount := 0
											for _, node := range nodes {
												if node.NotifyAddress == "" {
													continue
												}
												_, _, _, err := kdcDB.EncryptKeyForNode(activeKSK, node, kdcConf, kskDistributionID)
												if err != nil {
													log.Printf("KDC: Warning: Failed to encrypt KSK for node %s: %v", node.ID, err)
													continue
												}
												kskEncryptedCount++
											}
											log.Printf("KDC: Encrypted KSK %s for %d/%d nodes serving zone %s (distribution ID: %s)", activeKSK.ID, kskEncryptedCount, len(nodes), req.ZoneName, kskDistributionID)
										}
									}
								}
							}

							// Send NOTIFY to all active nodes with distributionID
							if kdcConf != nil && kdcConf.ControlZone != "" {
								if err := kdcDB.SendNotifyWithDistributionID(distributionID, kdcConf.ControlZone); err != nil {
									log.Printf("KDC: Warning: Failed to send NOTIFYs: %v", err)
									// Don't fail the request, just log the warning
								}
							} else {
								log.Printf("KDC: Warning: Control zone not configured, skipping NOTIFY")
							}

							resp.Msg = fmt.Sprintf("Key %s transitioned to distributed state. Distribution ID: %s. NOTIFYs sent to nodes.", req.KeyID, distributionID)
							// Reload key to get updated state
							key, _ = kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
							resp.Key = key
						}
					}
				}
			}

		case "transition":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for transition command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for transition command")
				return
			}

			// Get key and determine next state based on current state
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Key not found: %v", err)
			} else {
				var toState KeyState
				switch key.State {
				case KeyStateCreated:
					toState = KeyStatePublished
				case KeyStateStandby:
					toState = KeyStateActive
				default:
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Key %s is in state %s, which has no automatic transition. Use 'setstate' for manual state changes.", req.KeyID, key.State)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}

				if err := kdcDB.UpdateKeyState(req.ZoneName, req.KeyID, toState); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Key %s transitioned from %s to %s", req.KeyID, key.State, toState)
					key, _ = kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
					resp.Key = key
				}
			}

		case "delete-key":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for delete-key command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for delete-key command")
				return
			}

			// Check if key exists at KDC before deletion (safety check)
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
			if err != nil {
				// Check if it's a "not found" error
				if strings.Contains(err.Error(), "not found") {
					if !req.Force {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Key %s does not exist at KDC for zone %s. Use --force to delete anyway.", req.KeyID, req.ZoneName)
						break
					}
					// Force flag is set - log warning and continue
					log.Printf("KDC API: WARNING: Deleting key %s from zone %s at KDC that doesn't exist (force flag used)", req.KeyID, req.ZoneName)
				} else {
					// Actual database error
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to get key: %v", err)
					break
				}
			} else {
				// Key exists - check if it's in a dangerous state
				dangerousStates := map[KeyState]bool{
					KeyStateActive:     true,
					KeyStateActiveDist: true,
					KeyStateActiveCE:   true,
					KeyStateEdgeSigner: true,
				}

				if dangerousStates[key.State] && !req.Force {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Cannot delete key in state '%s' without force flag. Key is active.", key.State)
					break
				}
			}

			if err := kdcDB.DeleteDNSSECKey(req.ZoneName, req.KeyID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Key %s deleted successfully from KDC", req.KeyID)
			}

		case "purge-keys":
			// Purge keys in "removed" state (and "distributed" if force=true)
			// zone_name is optional - if provided, only purge keys for that zone
			var deletedCount int64
			var err error
			var states []KeyState

			if req.Force {
				// Delete both removed and distributed keys
				states = []KeyState{KeyStateRemoved, KeyStateDistributed}
			} else {
				// Only delete removed keys
				states = []KeyState{KeyStateRemoved}
			}

			totalDeleted := int64(0)
			for _, state := range states {
				deletedCount, err = kdcDB.DeleteKeysByState(state, req.ZoneName)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
					break
				}
				totalDeleted += deletedCount
			}

			if !resp.Error {
				var stateDesc string
				if req.Force {
					stateDesc = "'removed' and 'distributed'"
				} else {
					stateDesc = "'removed'"
				}
				if req.ZoneName != "" {
					resp.Msg = fmt.Sprintf("Deleted %d key(s) in %s state for zone %s", totalDeleted, stateDesc, req.ZoneName)
				} else {
					resp.Msg = fmt.Sprintf("Deleted %d key(s) in %s state (all zones)", totalDeleted, stateDesc)
				}
			}

		case "setstate":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for setstate command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for setstate command")
				return
			}
			if req.NewState == "" {
				sendJSONError(w, http.StatusBadRequest, "new_state is required for setstate command")
				return
			}

			newState := KeyState(req.NewState)
			// Validate state
			validStates := []KeyState{
				KeyStateCreated, KeyStatePublished, KeyStateStandby, KeyStateActive,
				KeyStateDistributed, KeyStateEdgeSigner, KeyStateRetired, KeyStateRemoved, KeyStateRevoked,
			}
			valid := false
			for _, vs := range validStates {
				if newState == vs {
					valid = true
					break
				}
			}
			if !valid {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Invalid state: %s", req.NewState)
			} else {
				if err := kdcDB.UpdateKeyState(req.ZoneName, req.KeyID, newState); err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Key %s state set to %s", req.KeyID, newState)
					key, _ := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
					resp.Key = key
				}
			}

		case "hash":
			if req.ZoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required for hash command")
				return
			}
			if req.KeyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required for hash command")
				return
			}
			key, err := kdcDB.GetDNSSECKeyByID(req.ZoneName, req.KeyID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				hash, err := computeKeyHash(key.PrivateKey)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = hash
				}
			}

		case "distrib-multi":
			if len(req.Zones) == 0 {
				sendJSONError(w, http.StatusBadRequest, "zones list is required for distrib-multi command")
				return
			}

			var results []DistributionResult
			successCount := 0
			errorCount := 0

			// Collect all keys from all zones first
			type ZoneKeyInfo struct {
				ZoneName   string
				StandbyZSK *DNSSECKey
				ActiveKSK  *DNSSECKey
				Nodes      []*Node
				Result     *DistributionResult
			}

			zoneInfos := make([]*ZoneKeyInfo, 0, len(req.Zones))
			allKeyIDs := make([]string, 0)
			allKeys := make([]*DNSSECKey, 0)

			// First pass: collect keys and validate zones
			for _, zoneName := range req.Zones {
				zoneInfo := &ZoneKeyInfo{
					ZoneName: zoneName,
					Result: &DistributionResult{
						ZoneName: zoneName,
						Status:   "error",
					},
				}

				// Find a standby ZSK for this zone
				keys, err := kdcDB.GetDNSSECKeysForZone(zoneName)
				if err != nil {
					zoneInfo.Result.Msg = fmt.Sprintf("Failed to get keys: %v", err)
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}

				// Get nodes for this zone
				nodes, err := kdcDB.GetActiveNodesForZone(zoneName)
				if err != nil {
					zoneInfo.Result.Msg = fmt.Sprintf("Failed to get nodes for zone: %v", err)
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}
				zoneInfo.Nodes = nodes

				// Check zone signing mode
				_, err = kdcDB.GetZone(zoneName)
				if err != nil {
					zoneInfo.Result.Msg = fmt.Sprintf("Failed to get zone: %v", err)
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}
				signingMode, err := kdcDB.GetZoneSigningMode(zoneName)
				if err != nil {
					zoneInfo.Result.Msg = fmt.Sprintf("Failed to get signing mode: %v", err)
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}
				if signingMode != ZoneSigningModeEdgesignDyn && signingMode != ZoneSigningModeEdgesignZsk && signingMode != ZoneSigningModeEdgesignFull {
					zoneInfo.Result.Msg = fmt.Sprintf("Zone has signing_mode=%s, keys are not distributed to nodes (only edgesign_* modes support key distribution)", signingMode)
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}

				// Find ZSK to distribute
				var standbyZSK *DNSSECKey
				for _, key := range keys {
					if key.KeyType == KeyTypeZSK && key.State == KeyStateStandby {
						standbyZSK = key
						break
					}
				}

				// Find KSK for edgesign_full zones
				var activeKSK *DNSSECKey
				if signingMode == ZoneSigningModeEdgesignFull {
					for _, key := range keys {
						if key.KeyType == KeyTypeKSK && key.State == KeyStateActive {
							activeKSK = key
							break
						}
					}
				}

				if standbyZSK == nil && activeKSK == nil {
					zoneInfo.Result.Msg = "No standby ZSK or active KSK found for zone"
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}

				if len(nodes) == 0 {
					zoneInfo.Result.Msg = fmt.Sprintf("No active nodes serve zone %s", zoneName)
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}

				// Check if any nodes have notify_address configured
				nodesWithNotify := 0
				for _, node := range nodes {
					if node.NotifyAddress != "" {
						nodesWithNotify++
					}
				}
				if nodesWithNotify == 0 {
					zoneInfo.Result.Msg = fmt.Sprintf("No nodes with notify_address configured for zone %s", zoneName)
					results = append(results, *zoneInfo.Result)
					errorCount++
					continue
				}

				zoneInfo.StandbyZSK = standbyZSK
				zoneInfo.ActiveKSK = activeKSK
				zoneInfos = append(zoneInfos, zoneInfo)

				// Collect key IDs for shared distribution ID
				if standbyZSK != nil {
					allKeyIDs = append(allKeyIDs, standbyZSK.ID)
					allKeys = append(allKeys, standbyZSK)
				}
				if activeKSK != nil {
					allKeyIDs = append(allKeyIDs, activeKSK.ID)
					allKeys = append(allKeys, activeKSK)
				}
			}

			// If no valid zones, return early
			if len(zoneInfos) == 0 {
				resp.Results = results
				if errorCount > 0 {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("No valid zones to distribute (all %d zones had errors)", len(req.Zones))
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
				return
			}

			// Create a single distribution ID for all keys across all zones
			// Use a hash of all zone names + all key IDs
			allZoneNames := make([]string, len(zoneInfos))
			for i, zi := range zoneInfos {
				allZoneNames[i] = zi.ZoneName
			}
			sort.Strings(allZoneNames)

			// Create distribution ID from sorted zone names and sorted key IDs
			// Use 4 bytes (8 hex chars) for shorter, more convenient IDs
			hash := sha256.New()
			for _, zoneName := range allZoneNames {
				hash.Write([]byte(zoneName))
			}
			for _, keyID := range allKeyIDs {
				hash.Write([]byte(keyID))
			}
			hashBytes := hash.Sum(nil)
			sharedDistributionID := hex.EncodeToString(hashBytes[:4])

			log.Printf("KDC: Created shared distribution ID %s for %d key(s) across %d zone(s)", sharedDistributionID, len(allKeys), len(zoneInfos))

			// Collect all unique nodes across all zones
			nodeMap := make(map[string]*Node)
			for _, zoneInfo := range zoneInfos {
				for _, node := range zoneInfo.Nodes {
					if node.NotifyAddress != "" {
						nodeMap[node.ID] = node
					}
				}
			}
			allNodes := make([]*Node, 0, len(nodeMap))
			for _, node := range nodeMap {
				allNodes = append(allNodes, node)
			}

			log.Printf("KDC: Will distribute %d key(s) to %d unique node(s) using shared distribution ID %s", len(allKeys), len(allNodes), sharedDistributionID)

			// Validate crypto backend before any state changes
			forcedCrypto := req.Crypto
			if forcedCrypto != "" && forcedCrypto != "jose" {
				sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid crypto backend: %s (must be 'jose')", forcedCrypto))
				return
			}

			// Second pass: encrypt all keys for all nodes using the shared distribution ID
			totalEncryptedCount := 0
			for _, zoneInfo := range zoneInfos {
				encryptedCount := 0

				// Update key states
				if zoneInfo.StandbyZSK != nil && zoneInfo.StandbyZSK.State == KeyStateStandby {
					if err := kdcDB.UpdateKeyState(zoneInfo.ZoneName, zoneInfo.StandbyZSK.ID, KeyStateDistributed); err != nil {
						zoneInfo.Result.Msg = fmt.Sprintf("Failed to update ZSK state: %v", err)
						results = append(results, *zoneInfo.Result)
						errorCount++
						continue
					}
				}

				if zoneInfo.ActiveKSK != nil && zoneInfo.ActiveKSK.State == KeyStateActive {
					if err := kdcDB.UpdateKeyState(zoneInfo.ZoneName, zoneInfo.ActiveKSK.ID, KeyStateActiveDist); err != nil {
						zoneInfo.Result.Msg = fmt.Sprintf("Failed to update KSK state: %v", err)
						results = append(results, *zoneInfo.Result)
						errorCount++
						continue
					}
				}

				// Encrypt keys for all nodes (each node gets all keys from all zones in this distribution)
				for _, node := range allNodes {
					if zoneInfo.StandbyZSK != nil {
						_, _, _, err := kdcDB.EncryptKeyForNodeWithCrypto(zoneInfo.StandbyZSK, node, kdcConf, forcedCrypto, sharedDistributionID)
						if err != nil {
							log.Printf("KDC: Warning: Failed to encrypt ZSK %s for node %s: %v", zoneInfo.StandbyZSK.ID, node.ID, err)
							continue
						}
						encryptedCount++
					}

					if zoneInfo.ActiveKSK != nil {
						_, _, _, err := kdcDB.EncryptKeyForNodeWithCrypto(zoneInfo.ActiveKSK, node, kdcConf, forcedCrypto, sharedDistributionID)
						if err != nil {
							log.Printf("KDC: Warning: Failed to encrypt KSK %s for node %s: %v", zoneInfo.ActiveKSK.ID, node.ID, err)
							continue
						}
						encryptedCount++
					}
				}

				totalEncryptedCount += encryptedCount

				zoneInfo.Result.Status = "success"
				keyCount := 0
				if zoneInfo.StandbyZSK != nil {
					keyCount++
					zoneInfo.Result.KeyID = zoneInfo.StandbyZSK.ID
				}
				if zoneInfo.ActiveKSK != nil {
					keyCount++
					if zoneInfo.Result.KeyID == "" {
						zoneInfo.Result.KeyID = zoneInfo.ActiveKSK.ID
					}
				}

				zoneInfo.Result.Msg = fmt.Sprintf("%d key distributed (distribution ID: %s) to %d node(s)", keyCount, sharedDistributionID, len(allNodes))
				results = append(results, *zoneInfo.Result)
				successCount++
			}

			// Send a single NOTIFY for the shared distribution
			if kdcConf != nil && kdcConf.ControlZone != "" && sharedDistributionID != "" && totalEncryptedCount > 0 {
				if err := kdcDB.SendNotifyWithDistributionID(sharedDistributionID, kdcConf.ControlZone); err != nil {
					log.Printf("KDC: Warning: Failed to send NOTIFY for shared distribution %s: %v", sharedDistributionID, err)
				} else {
					log.Printf("KDC: Successfully sent NOTIFY for shared distribution %s", sharedDistributionID)
				}
			}

			resp.Results = results
			if errorCount == 0 {
				resp.Msg = fmt.Sprintf("Successfully distributed keys for %d zone(s)", successCount)
			} else if successCount == 0 {
				// Check if all failures are due to signing mode
				allSigningModeErrors := true
				for _, result := range results {
					if result.Status == "error" && !strings.Contains(result.Msg, "signing_mode") {
						allSigningModeErrors = false
						break
					}
				}
				if allSigningModeErrors {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Request denied: all %d zone(s) have signing_mode=central (keys are not distributed for central mode; use edgesign_* modes for key distribution)", errorCount)
				} else {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to distribute keys for all %d zone(s)", errorCount)
				}
			} else {
				resp.Msg = fmt.Sprintf("Distributed keys for %d/%d zone(s) (%d failed)", successCount, len(req.Zones), errorCount)
			}

		default:
			http.Error(w, fmt.Sprintf("Unknown command: %s", req.Command), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcNode handles node management endpoints
func APIKdcNode(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcNode handler called")
		}
		var req KdcNodePost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcNodeResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Node == nil {
				sendJSONError(w, http.StatusBadRequest, "node is required for add command")
				return
			}
			if req.Node.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "node.id is required")
				return
			}
			// Require the node's JOSE public key
			if len(req.Node.LongTermJosePubKey) == 0 {
				sendJSONError(w, http.StatusBadRequest, "node must include a JOSE public key (long_term_jose_pub_key)")
				return
			}
			if req.Node.State == "" {
				req.Node.State = NodeStateOnline // Default to online
			}
			if err := kdcDB.AddNode(req.Node); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s added successfully", req.Node.ID)
			}

		case "list":
			nodes, err := kdcDB.GetAllNodes()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Nodes = nodes
			}

		case "get":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for get command")
				return
			}
			node, err := kdcDB.GetNode(req.NodeID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Node = node
			}

		case "update":
			if req.Node == nil || req.Node.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "node with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateNode(req.Node); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s updated successfully", req.Node.ID)
			}

		case "set-state":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for set-state command")
				return
			}
			if req.State == "" {
				sendJSONError(w, http.StatusBadRequest, "state is required for set-state command")
				return
			}
			state := NodeState(req.State)
			if state != NodeStateOnline && state != NodeStateOffline && state != NodeStateCompromised && state != NodeStateSuspended {
				sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid state: %s (must be online, offline, compromised, or suspended)", req.State))
				return
			}
			if err := kdcDB.UpdateNodeState(req.NodeID, state); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s state set to %s", req.NodeID, state)
			}

		case "delete":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for delete command")
				return
			}
			if err := kdcDB.DeleteNode(req.NodeID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Node %s deleted successfully", req.NodeID)
			}

		default:
			http.Error(w, fmt.Sprintf("Unknown command: %s", req.Command), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// KdcEnrollmentPost represents a request to the KDC enrollment API
type KdcEnrollmentPost struct {
	Command          string `json:"command"`                     // "generate", "activate", "list", "status", "purge", "mark-used"
	NodeID           string `json:"node_id,omitempty"`           // For generate, activate, status commands
	TokenValue       string `json:"token_value,omitempty"`       // For mark-used command
	ExpirationWindow string `json:"expiration_window,omitempty"` // For activate command (e.g., "5m", "1h")
	Comment          string `json:"comment,omitempty"`           // For generate command
	Crypto           string `json:"crypto,omitempty"`            // For generate command: crypto backend ("jose")
	DeleteFiles      bool   `json:"delete_files,omitempty"`      // For purge command
}

// KdcEnrollmentResponse represents a response from the KDC enrollment API
type KdcEnrollmentResponse struct {
	Time     time.Time          `json:"time"`
	Error    bool               `json:"error,omitempty"`
	ErrorMsg string             `json:"error_msg,omitempty"`
	Msg      string             `json:"msg,omitempty"`
	Token    *EnrollmentToken   `json:"token,omitempty"`
	Tokens   []*EnrollmentToken `json:"tokens,omitempty"`
	Status   string             `json:"status,omitempty"`
	// BlobPath    string           `json:"blob_path,omitempty"`    // For generate command (deprecated - use blob_content)
	BlobContent string `json:"blob_content,omitempty"` // For generate command: base64-encoded blob content
	Count       int    `json:"count,omitempty"`        // For purge command
}

// KdcConfigPost represents a request to the KDC config API
type KdcConfigPost struct {
	Command string `json:"command"` // "get"
}

// KdcConfigResponse represents a response from the KDC config API
type KdcConfigResponse struct {
	Time     time.Time              `json:"time"`
	Error    bool                   `json:"error,omitempty"`
	ErrorMsg string                 `json:"error_msg,omitempty"`
	Config   map[string]interface{} `json:"config,omitempty"`
}

// APIKdcEnrollment handles enrollment token management endpoints
func APIKdcEnrollment(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcEnrollment handler called")
		}
		var req KdcEnrollmentPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcEnrollmentResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "generate":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for generate command")
				return
			}

			// Check if node already exists and is active
			existingNode, err := kdcDB.GetNode(req.NodeID)
			if err == nil {
				// Node exists - check if it's in an active state
				if existingNode.State == NodeStateOnline {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Node %s already exists and is online. Cannot generate enrollment package for an active node. Delete the node first (kdc-cli node delete --nodeid %s) or set it to a non-active state (suspended/offline) before re-enrolling.", req.NodeID, req.NodeID)
					break
				}
				// Node exists but is not online (offline, suspended, compromised) - allow re-enrollment
				// This is intentional - nodes in these states may need to re-enroll
			}
			// If node doesn't exist (err != nil), that's fine - it's a new node

			// Check if token already exists
			status, err := kdcDB.GetEnrollmentTokenStatus(req.NodeID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else if status != "not_found" {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Enrollment token already exists for node %s (status: %s)", req.NodeID, status)
			} else {
				// Validate crypto backend before generating token to avoid orphaned tokens
				// Get crypto backend from request (optional, defaults to JOSE if empty)
				cryptoBackend := ""
				if req.Crypto != "" {
					cryptoBackend = req.Crypto
					// Validate crypto backend if specified
					if cryptoBackend != "jose" {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("invalid crypto backend: %s (must be 'jose')", cryptoBackend)
					}
				}

				// Only proceed if validation passed
				if !resp.Error {
					// Generate token
					token, err := kdcDB.GenerateEnrollmentToken(req.NodeID)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						// Generate enrollment blob content (CLI will write the file)
						blobContent, err := GenerateEnrollmentBlobContent(req.NodeID, token, kdcConf, cryptoBackend)
						if err != nil {
							// Set error in response - blob generation is required
							resp.Error = true
							resp.ErrorMsg = err.Error()
							// Token was already created, but blob generation failed
							// This is a critical error since the blob is required for enrollment
							// Clean up the orphaned token by deleting it
							if deleteErr := kdcDB.DeleteEnrollmentToken(token.TokenValue); deleteErr != nil {
								log.Printf("KDC: Warning: Failed to delete orphaned enrollment token for node %s after blob generation failure: %v", req.NodeID, deleteErr)
							} else {
								log.Printf("KDC: Deleted orphaned enrollment token for node %s after blob generation failure", req.NodeID)
							}
						} else {
							// Only set Token and Msg after successful blob generation
							resp.Token = token
							resp.Msg = fmt.Sprintf("Enrollment token generated for node: %s", req.NodeID)
							resp.BlobContent = blobContent
						}
					}
				}
			}

		case "activate":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for activate command")
				return
			}

			expirationWindow := kdcConf.GetEnrollmentExpirationWindow()
			if req.ExpirationWindow != "" {
				var err error
				expirationWindow, err = time.ParseDuration(req.ExpirationWindow)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Invalid expiration_window format: %v", err)
					break
				}
			}

			// Check token status
			status, err := kdcDB.GetEnrollmentTokenStatus(req.NodeID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else if status == "not_found" {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("No enrollment token found for node %s", req.NodeID)
			} else if status == "active" {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Enrollment token for node %s is already activated", req.NodeID)
			} else if status == "completed" {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Enrollment token for node %s has already been used", req.NodeID)
			} else {
				err := kdcDB.ActivateEnrollmentToken(req.NodeID, expirationWindow)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Enrollment token activated for node: %s", req.NodeID)
				}
			}

		case "list":
			tokens, err := kdcDB.ListEnrollmentTokens()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Tokens = tokens
				resp.Msg = fmt.Sprintf("Found %d enrollment token(s)", len(tokens))
			}

		case "status":
			if req.NodeID == "" {
				sendJSONError(w, http.StatusBadRequest, "node_id is required for status command")
				return
			}

			status, err := kdcDB.GetEnrollmentTokenStatus(req.NodeID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Status = status
				if status != "not_found" {
					// Get token details
					tokens, err := kdcDB.ListEnrollmentTokens()
					if err == nil {
						for _, t := range tokens {
							if t.NodeID == req.NodeID {
								resp.Token = t
								break
							}
						}
					}
				}
			}

		case "purge":
			count, err := kdcDB.PurgeEnrollmentTokens()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Count = count
				resp.Msg = fmt.Sprintf("Purged %d enrollment token(s)", count)

				// Optionally delete blob files
				if req.DeleteFiles && count > 0 {
					tokens, _ := kdcDB.ListEnrollmentTokens()
					deletedFiles := 0
					for _, token := range tokens {
						status, _ := kdcDB.GetEnrollmentTokenStatus(token.NodeID)
						if status == "expired" || status == "completed" {
							blobFile := fmt.Sprintf("%s.enroll", token.NodeID)
							if err := os.Remove(blobFile); err == nil {
								deletedFiles++
							}
						}
					}
					if deletedFiles > 0 {
						resp.Msg += fmt.Sprintf(", deleted %d blob file(s)", deletedFiles)
					}
				}
			}

		case "mark-used":
			if req.TokenValue == "" {
				sendJSONError(w, http.StatusBadRequest, "token_value is required for mark-used command")
				return
			}

			err := kdcDB.MarkEnrollmentTokenUsed(req.TokenValue)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = "Enrollment token marked as used"
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcConfig handles KDC configuration endpoints
// conf is *tdns.Config passed as interface{} to avoid circular import
// kdcConf is *tnm.KdcConf
func APIKdcConfig(kdcConf *tnm.KdcConf, tdnsConf interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcConfig handler called")
		}
		var req KdcConfigPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcConfigResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "get":
			// Extract DNS and API addresses from tdns config
			dnsAddresses := []string{}
			apiAddresses := []string{}
			if configMap, ok := tdnsConf.(map[string]interface{}); ok {
				if dnsEngine, ok := configMap["DnsEngine"].(map[string]interface{}); ok {
					if addrs, ok := dnsEngine["Addresses"].([]string); ok {
						dnsAddresses = addrs
					}
				}
				if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
					if addrs, ok := apiServer["Addresses"].([]string); ok {
						apiAddresses = addrs
					}
				}
			}

			configResp := map[string]interface{}{
				"control_zone":          kdcConf.ControlZone,
				"default_algorithm":     kdcConf.DefaultAlgorithm,
				"key_rotation_interval": kdcConf.KeyRotationInterval.String(),
				"standby_key_count":     kdcConf.StandbyKeyCount,
				"chunk_max_size":        kdcConf.GetChunkMaxSize(),
				"dns_addresses":         dnsAddresses,
				"api_addresses":         apiAddresses,
			}
			resp.Config = configResp

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// KdcDistribPost represents a request to the KDC distrib API
type KdcDistribPost struct {
	Command        string `json:"command"`                   // "list", "state", "completed", "purge", "purge-force"
	DistributionID string `json:"distribution_id,omitempty"` // For state and completed commands
	Force          bool   `json:"force,omitempty"`           // For purge command: if true, delete all distributions
}

// DistributionStateInfo represents detailed information about a distribution
type DistributionStateInfo struct {
	DistributionID string   `json:"distribution_id"`
	ZoneName       string   `json:"zone_name"`
	KeyID          string   `json:"key_id"`
	KeyState       string   `json:"key_state"`
	CreatedAt      string   `json:"created_at"`
	TargetNodes    []string `json:"target_nodes"`    // All nodes that should receive this distribution
	ConfirmedNodes []string `json:"confirmed_nodes"` // Nodes that have confirmed
	PendingNodes   []string `json:"pending_nodes"`   // Nodes that haven't confirmed yet
	AllConfirmed   bool     `json:"all_confirmed"`
	CompletedAt    *string  `json:"completed_at,omitempty"` // When distribution was completed
}

// KdcDistribResponse represents a response from the KDC distrib API
type KdcDistribResponse struct {
	Time          time.Time                 `json:"time"`
	Error         bool                      `json:"error,omitempty"`
	ErrorMsg      string                    `json:"error_msg,omitempty"`
	Msg           string                    `json:"msg,omitempty"`
	Distributions []string                  `json:"distributions,omitempty"` // For list command (simple format)
	Summaries     []DistributionSummaryInfo `json:"summaries,omitempty"`     // For list command (detailed format)
	State         *DistributionStateInfo    `json:"state,omitempty"`         // For state command
}

// APIKdcDistrib handles distribution management endpoints
func APIKdcDistrib(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcDistrib handler called")
		}
		var req KdcDistribPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcDistribResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "list":
			// Get detailed distribution summaries
			summaries, err := kdcDB.GetDistributionSummaries()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Summaries = summaries
				// Also include simple list for backward compatibility
				distIDs := make([]string, len(summaries))
				for i, s := range summaries {
					distIDs[i] = s.DistributionID
				}
				resp.Distributions = distIDs
				resp.Msg = fmt.Sprintf("Found %d distribution(s)", len(summaries))
			}

		case "purge":
			// Delete all completed distributions (or all if force=true)
			var deleted int
			var err error
			if req.Force {
				deleted, err = kdcDB.PurgeAllDistributions()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Purged %d distribution(s) (force mode)", deleted)
				}
			} else {
				deleted, err = kdcDB.PurgeCompletedDistributions()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Msg = fmt.Sprintf("Purged %d completed distribution(s)", deleted)
				}
			}

		case "state":
			if req.DistributionID == "" {
				sendJSONError(w, http.StatusBadRequest, "distribution_id is required for state command")
				return
			}

			// Get distribution records
			records, err := kdcDB.GetDistributionRecordsForDistributionID(req.DistributionID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else if len(records) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Distribution %s not found", req.DistributionID)
			} else {
				// Use first record to get zone/key info
				record := records[0]

				// Get key state
				key, err := kdcDB.GetDNSSECKeyByID(record.ZoneName, record.KeyID)
				keyState := "unknown"
				if err == nil {
					keyState = string(key.State)
				}

				// Get target nodes (nodes that serve this zone via components)
				zoneNodes, _ := kdcDB.GetActiveNodesForZone(record.ZoneName)
				var targetNodes []string
				for _, node := range zoneNodes {
					if node.NotifyAddress != "" {
						targetNodes = append(targetNodes, node.ID)
					}
				}

				// Get confirmed nodes
				confirmedNodes, _ := kdcDB.GetDistributionConfirmations(req.DistributionID)

				// Calculate pending nodes
				confirmedMap := make(map[string]bool)
				for _, nodeID := range confirmedNodes {
					confirmedMap[nodeID] = true
				}
				var pendingNodes []string
				for _, nodeID := range targetNodes {
					if !confirmedMap[nodeID] {
						pendingNodes = append(pendingNodes, nodeID)
					}
				}

				allConfirmed := len(pendingNodes) == 0 && len(targetNodes) > 0

				resp.State = &DistributionStateInfo{
					DistributionID: req.DistributionID,
					ZoneName:       record.ZoneName,
					KeyID:          record.KeyID,
					KeyState:       keyState,
					CreatedAt:      record.CreatedAt.Format(time.RFC3339),
					TargetNodes:    targetNodes,
					ConfirmedNodes: confirmedNodes,
					PendingNodes:   pendingNodes,
					AllConfirmed:   allConfirmed,
				}
				resp.Msg = fmt.Sprintf("Distribution %s: %d/%d nodes confirmed", req.DistributionID, len(confirmedNodes), len(targetNodes))
			}

		case "completed":
			if req.DistributionID == "" {
				sendJSONError(w, http.StatusBadRequest, "distribution_id is required for completed command")
				return
			}

			// Get distribution records to find zone/key
			records, err := kdcDB.GetDistributionRecordsForDistributionID(req.DistributionID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else if len(records) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Distribution %s not found", req.DistributionID)
			} else {
				record := records[0]

				// Force transition key state from 'distributed' to 'edgesigner'
				if err := kdcDB.UpdateKeyState(record.ZoneName, record.KeyID, KeyStateEdgeSigner); err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Failed to update key state: %v", err)
				} else {
					resp.Msg = fmt.Sprintf("Distribution %s marked as completed. Key %s transitioned to 'edgesigner' state.", req.DistributionID, record.KeyID)
				}
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// computeKeyHash computes a SHA-256 hash of the private key material
// Returns hex-encoded hash string
func computeKeyHash(privateKey []byte) (string, error) {
	if len(privateKey) == 0 {
		return "", fmt.Errorf("private key is empty")
	}
	hash := sha256.Sum256(privateKey)
	return hex.EncodeToString(hash[:]), nil
}

// APIKdcOperations handles operation requests (ping, delete_key, roll_key)
func APIKdcOperations(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcOperations handler called")
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := map[string]interface{}{
			"time":  time.Now(),
			"error": false,
		}

		command, ok := req["command"].(string)
		if !ok {
			sendJSONError(w, http.StatusBadRequest, "command is required")
			return
		}

		switch command {
		case "ping":
			// Handle ping operation
			var nodeIDs []string

			if all, ok := req["all"].(bool); ok && all {
				// Ping all active nodes
				nodes, err := kdcDB.GetActiveNodes()
				if err != nil {
					resp["error"] = true
					resp["error_msg"] = fmt.Sprintf("Failed to get active nodes: %v", err)
					break
				}
				for _, node := range nodes {
					nodeIDs = append(nodeIDs, node.ID)
				}
			} else if nodeID, ok := req["node_id"].(string); ok && nodeID != "" {
				// Ping specific node
				nodeIDs = []string{nodeID}
			} else {
				sendJSONError(w, http.StatusBadRequest, "either 'node_id' or 'all' must be specified")
				return
			}

			if len(nodeIDs) == 0 {
				resp["error"] = true
				resp["error_msg"] = "No nodes to ping"
				break
			}

			// Extract forced crypto if specified
			forcedCrypto := ""
			if crypto, ok := req["crypto"].(string); ok && crypto != "" {
				// Validate crypto backend at API boundary
				if crypto != "jose" {
					sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid crypto backend: %s (must be 'jose')", crypto))
					return
				}
				forcedCrypto = crypto
			}

			// Create ping operations for each node
			var distributionIDs []string
			for _, nodeID := range nodeIDs {
				distID, err := kdcDB.CreatePingOperation(nodeID, kdcConf, forcedCrypto)
				if err != nil {
					log.Printf("KDC API: Failed to create ping operation for node %s: %v", nodeID, err)
					continue
				}
				distributionIDs = append(distributionIDs, distID)

				// Send NOTIFY for this distribution
				if err := kdcDB.SendNotifyWithDistributionID(distID, kdcConf.ControlZone); err != nil {
					log.Printf("KDC API: Failed to send NOTIFY for distribution %s: %v", distID, err)
				}
			}

			if len(distributionIDs) == 0 {
				resp["error"] = true
				resp["error_msg"] = "Failed to create any ping operations"
			} else {
				resp["msg"] = fmt.Sprintf("Ping operation sent to %d node(s)", len(distributionIDs))
				resp["distribution_ids"] = distributionIDs
			}

		case "delete_key":
			// Handle delete_key operation
			zoneName, ok := req["zone_name"].(string)
			if !ok || zoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required")
				return
			}
			keyID, ok := req["key_id"].(string)
			if !ok || keyID == "" {
				sendJSONError(w, http.StatusBadRequest, "key_id is required")
				return
			}
			reason, _ := req["reason"].(string)
			force, _ := req["force"].(bool)

			// Check if key exists at KDC before distributing delete operation
			key, err := kdcDB.GetDNSSECKeyByID(zoneName, keyID)
			if err != nil {
				// Check if it's a "not found" error
				if strings.Contains(err.Error(), "not found") {
					if !force {
						resp["error"] = true
						resp["error_msg"] = fmt.Sprintf("Key %s does not exist at KDC for zone %s. Use --force to delete anyway (key may exist at nodes).", keyID, zoneName)
						break
					}
					// Force flag is set - log warning and continue
					log.Printf("KDC API: WARNING: Deleting key %s from zone %s that doesn't exist at KDC (force flag used)", keyID, zoneName)
				} else {
					// Actual database error
					resp["error"] = true
					resp["error_msg"] = fmt.Sprintf("Failed to get key: %v", err)
					break
				}
			} else {
				// Key exists - check if it's in a dangerous state
				dangerousStates := map[KeyState]bool{
					KeyStateActive:     true,
					KeyStateActiveDist: true,
					KeyStateActiveCE:   true,
					KeyStateEdgeSigner: true,
				}

				if dangerousStates[key.State] && !force {
					resp["error"] = true
					resp["error_msg"] = fmt.Sprintf("Cannot delete key in state '%s' without force flag. Key is active.", key.State)
					break
				}
			}

			// Optional: specific node ID (if provided, only send to this node)
			targetNodeID, _ := req["node_id"].(string)

			// Determine which nodes to target
			var nodes []*Node

			if targetNodeID != "" {
				// Single specific node
				node, err := kdcDB.GetNode(targetNodeID)
				if err != nil {
					resp["error"] = true
					resp["error_msg"] = fmt.Sprintf("Failed to get node %s: %v", targetNodeID, err)
					break
				}
				nodes = append(nodes, node)
			} else {
				// All nodes serving this zone
				nodes, err = kdcDB.GetActiveNodesForZone(zoneName)
				if err != nil {
					resp["error"] = true
					resp["error_msg"] = fmt.Sprintf("Failed to get nodes for zone: %v", err)
					break
				}

				if len(nodes) == 0 {
					resp["error"] = true
					resp["error_msg"] = fmt.Sprintf("No nodes serving zone %s", zoneName)
					break
				}
			}

			// Create delete_key operations for each target node
			var distributionIDs []string
			for _, node := range nodes {
				distID, err := kdcDB.CreateDeleteKeyOperation(zoneName, keyID, node.ID, reason)
				if err != nil {
					log.Printf("KDC API: Failed to create delete_key operation for node %s: %v", node.ID, err)
					continue
				}
				distributionIDs = append(distributionIDs, distID)

				// Send NOTIFY for this distribution
				if err := kdcDB.SendNotifyWithDistributionID(distID, kdcConf.ControlZone); err != nil {
					log.Printf("KDC API: Failed to send NOTIFY for distribution %s: %v", distID, err)
				}
			}

			if len(distributionIDs) == 0 {
				resp["error"] = true
				resp["error_msg"] = "Failed to create any delete_key operations"
			} else {
				resp["msg"] = fmt.Sprintf("Delete key operation sent to %d node(s)", len(distributionIDs))
				resp["distribution_ids"] = distributionIDs
				resp["nodes_notified"] = len(distributionIDs)
			}

		case "roll_key":
			// Handle roll_key operation
			zoneName, ok := req["zone_name"].(string)
			if !ok || zoneName == "" {
				sendJSONError(w, http.StatusBadRequest, "zone_name is required")
				return
			}
			keyType, ok := req["key_type"].(string)
			if !ok || keyType == "" {
				sendJSONError(w, http.StatusBadRequest, "key_type is required")
				return
			}
			oldKeyID, _ := req["old_key_id"].(string)

			// Validate key type
			var keyTypeEnum KeyType
			switch strings.ToUpper(keyType) {
			case "ZSK":
				keyTypeEnum = KeyTypeZSK
			case "KSK":
				keyTypeEnum = KeyTypeKSK
			case "CSK":
				keyTypeEnum = KeyTypeCSK
			default:
				sendJSONError(w, http.StatusBadRequest, "key_type must be ZSK, KSK, or CSK")
				return
			}

			// Generate new key using default algorithm
			algorithm := kdcConf.DefaultAlgorithm
			if algorithm == 0 {
				algorithm = 15 // ED25519 as fallback default
			}
			newKey, err := kdcDB.GenerateDNSSECKey(zoneName, keyTypeEnum, algorithm, "API roll_key operation")
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = fmt.Sprintf("Failed to generate new key: %v", err)
				break
			}

			// Get all nodes serving this zone
			nodes, err := kdcDB.GetActiveNodesForZone(zoneName)
			if err != nil {
				resp["error"] = true
				resp["error_msg"] = fmt.Sprintf("Failed to get nodes for zone: %v", err)
				break
			}

			if len(nodes) == 0 {
				resp["error"] = true
				resp["error_msg"] = fmt.Sprintf("No nodes serving zone %s", zoneName)
				break
			}

			// Create roll_key operations for each node
			var distributionIDs []string
			for _, node := range nodes {
				distID, err := kdcDB.CreateRollKeyOperation(newKey, oldKeyID, node, kdcConf)
				if err != nil {
					log.Printf("KDC API: Failed to create roll_key operation for node %s: %v", node.ID, err)
					continue
				}
				distributionIDs = append(distributionIDs, distID)

				// Send NOTIFY for this distribution
				if err := kdcDB.SendNotifyWithDistributionID(distID, kdcConf.ControlZone); err != nil {
					log.Printf("KDC API: Failed to send NOTIFY for distribution %s: %v", distID, err)
				}
			}

			if len(distributionIDs) == 0 {
				resp["error"] = true
				resp["error_msg"] = "Failed to create any roll_key operations"
			} else {
				resp["msg"] = fmt.Sprintf("Roll key operation sent to %d node(s)", len(distributionIDs))
				resp["distribution_ids"] = distributionIDs
				resp["new_key_id"] = newKey.KeyID
				if oldKeyID != "" {
					resp["old_key_id"] = oldKeyID
				}
				resp["nodes_notified"] = len(distributionIDs)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// SetupKdcAPIRoutes sets up KDC-specific API routes
// conf is *tdns.Config passed as interface{} to avoid circular import
// APIKdcService handles service management endpoints
func APIKdcService(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcService handler called")
		}
		var req KdcServicePost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcServiceResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Service == nil {
				sendJSONError(w, http.StatusBadRequest, "service is required for add command")
				return
			}
			if req.Service.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "service.id is required")
				return
			}
			if err := kdcDB.AddService(req.Service); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Service %s added successfully", req.Service.ID)
			}

		case "list":
			services, err := kdcDB.GetAllServices()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Services = services
			}

		case "get":
			serviceID := req.ServiceID
			if serviceID == "" && req.ServiceName != "" {
				// Look up by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, s := range services {
						if s.Name == req.ServiceName {
							serviceID = s.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					}
				}
			}
			if serviceID == "" {
				sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for get command")
				return
			}
			service, err := kdcDB.GetService(serviceID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Service = service
			}

		case "update":
			if req.Service == nil || req.Service.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "service with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateService(req.Service); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Service %s updated successfully", req.Service.ID)
			}

		case "delete":
			serviceID := req.ServiceID
			if serviceID == "" && req.ServiceName != "" {
				// Look up by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, s := range services {
						if s.Name == req.ServiceName {
							serviceID = s.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					}
				}
			}
			if serviceID == "" {
				sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for delete command")
				return
			}
			if err := kdcDB.DeleteService(serviceID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Service %s deleted successfully", serviceID)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcComponent handles component management endpoints
func APIKdcComponent(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcComponent handler called")
		}
		var req KdcComponentPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcComponentResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "add":
			if req.Component == nil {
				sendJSONError(w, http.StatusBadRequest, "component is required for add command")
				return
			}
			if req.Component.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "component.id is required")
				return
			}
			if err := kdcDB.AddComponent(req.Component); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Component %s added successfully", req.Component.ID)
			}

		case "list":
			components, err := kdcDB.GetAllComponents()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Components = components
			}

		case "get":
			componentID := req.ComponentID
			if componentID == "" && req.ComponentName != "" {
				// Look up by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, c := range components {
						if c.Name == req.ComponentName {
							componentID = c.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Component not found: %s", req.ComponentName)
					}
				}
			}
			if componentID == "" {
				sendJSONError(w, http.StatusBadRequest, "component_id or component_name is required for get command")
				return
			}
			component, err := kdcDB.GetComponent(componentID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Component = component
			}

		case "update":
			if req.Component == nil || req.Component.ID == "" {
				sendJSONError(w, http.StatusBadRequest, "component with ID is required for update command")
				return
			}
			if err := kdcDB.UpdateComponent(req.Component); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Component %s updated successfully", req.Component.ID)
			}

		case "delete":
			componentID := req.ComponentID
			if componentID == "" && req.ComponentName != "" {
				// Look up by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					found := false
					for _, c := range components {
						if c.Name == req.ComponentName {
							componentID = c.ID
							found = true
							break
						}
					}
					if !found {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Component not found: %s", req.ComponentName)
					}
				}
			}
			if componentID == "" {
				sendJSONError(w, http.StatusBadRequest, "component_id or component_name is required for delete command")
				return
			}
			if err := kdcDB.DeleteComponent(componentID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Component %s deleted successfully", componentID)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcServiceComponent handles service-component assignment endpoints
func APIKdcServiceComponent(kdcDB *KdcDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcServiceComponent handler called")
		}
		var req KdcServiceComponentPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcServiceComponentResponse{
			Time: time.Now(),
		}

		// Helper to resolve service ID from name or ID
		resolveServiceID := func() (string, error) {
			if req.ServiceID != "" {
				// Check if it's a valid service ID
				_, err := kdcDB.GetService(req.ServiceID)
				if err != nil {
					return "", fmt.Errorf("service not found: %s", req.ServiceID)
				}
				return req.ServiceID, nil
			}
			if req.ServiceName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetService(req.ServiceName)
				if err == nil {
					return req.ServiceName, nil
				}
				// If not found by ID, try to find by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					return "", err
				}
				for _, s := range services {
					if s.Name == req.ServiceName {
						return s.ID, nil
					}
				}
				return "", fmt.Errorf("service not found: %s", req.ServiceName)
			}
			return "", fmt.Errorf("service_id or service_name is required")
		}

		// Helper to resolve component ID from name or ID
		resolveComponentID := func() (string, error) {
			if req.ComponentID != "" {
				// Check if it's a valid component ID
				_, err := kdcDB.GetComponent(req.ComponentID)
				if err != nil {
					return "", fmt.Errorf("component not found: %s", req.ComponentID)
				}
				return req.ComponentID, nil
			}
			if req.ComponentName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetComponent(req.ComponentName)
				if err == nil {
					return req.ComponentName, nil
				}
				// If not found by ID, try to find by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					return "", err
				}
				for _, c := range components {
					if c.Name == req.ComponentName {
						return c.ID, nil
					}
				}
				return "", fmt.Errorf("component not found: %s", req.ComponentName)
			}
			return "", fmt.Errorf("component_id or component_name is required")
		}

		switch req.Command {
		case "add":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if err := kdcDB.AddServiceComponentAssignment(serviceID, componentID); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Component %s assigned to service %s", componentID, serviceID)
					}
				}
			}

		case "replace":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				// Resolve old component ID
				oldComponentID := req.OldComponentID
				if oldComponentID == "" && req.OldComponentName != "" {
					// First try by ID
					_, err := kdcDB.GetComponent(req.OldComponentName)
					if err == nil {
						oldComponentID = req.OldComponentName
					} else {
						// Try by name
						components, err := kdcDB.GetAllComponents()
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = err.Error()
						} else {
							found := false
							for _, c := range components {
								if c.Name == req.OldComponentName {
									oldComponentID = c.ID
									found = true
									break
								}
							}
							if !found {
								resp.Error = true
								resp.ErrorMsg = fmt.Sprintf("Old component not found: %s", req.OldComponentName)
							}
						}
					}
				}
				if oldComponentID == "" {
					resp.Error = true
					resp.ErrorMsg = "old_component_id or old_component_name is required for replace command"
				} else {
					// Resolve new component ID
					newComponentID := req.NewComponentID
					if newComponentID == "" && req.NewComponentName != "" {
						// First try by ID
						_, err := kdcDB.GetComponent(req.NewComponentName)
						if err == nil {
							newComponentID = req.NewComponentName
						} else {
							// Try by name
							components, err := kdcDB.GetAllComponents()
							if err != nil {
								resp.Error = true
								resp.ErrorMsg = err.Error()
							} else {
								found := false
								for _, c := range components {
									if c.Name == req.NewComponentName {
										newComponentID = c.ID
										found = true
										break
									}
								}
								if !found {
									resp.Error = true
									resp.ErrorMsg = fmt.Sprintf("New component not found: %s", req.NewComponentName)
								}
							}
						}
					}
					if newComponentID == "" {
						resp.Error = true
						resp.ErrorMsg = "new_component_id or new_component_name is required for replace command"
					} else {
						if err := kdcDB.ReplaceServiceComponentAssignment(serviceID, oldComponentID, newComponentID); err != nil {
							resp.Error = true
							resp.ErrorMsg = err.Error()
						} else {
							resp.Msg = fmt.Sprintf("Component %s replaced with %s in service %s", oldComponentID, newComponentID, serviceID)
						}
					}
				}
			}

		case "delete":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if err := kdcDB.RemoveServiceComponentAssignment(serviceID, componentID); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Component %s removed from service %s", componentID, serviceID)
					}
				}
			}

		case "list":
			serviceID, err := resolveServiceID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentIDs, err := kdcDB.GetComponentsForService(serviceID)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					// Convert to ServiceComponentAssignment structs
					assignments := make([]*ServiceComponentAssignment, 0, len(componentIDs))
					for _, compID := range componentIDs {
						assignments = append(assignments, &ServiceComponentAssignment{
							ServiceID:   serviceID,
							ComponentID: compID,
							Active:      true,
						})
					}
					resp.Assignments = assignments
				}
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcNodeComponent handles node-component assignment endpoints
func APIKdcNodeComponent(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcNodeComponent handler called")
		}
		var req KdcNodeComponentPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("KDC: APIKdcNodeComponent: Invalid request: %v", err)
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		log.Printf("KDC: APIKdcNodeComponent: Received %s command (node_id=%s, node_name=%s, component_id=%s, component_name=%s)",
			req.Command, req.NodeID, req.NodeName, req.ComponentID, req.ComponentName)

		resp := KdcNodeComponentResponse{
			Time: time.Now(),
		}

		// Helper to resolve node ID from name or ID
		resolveNodeID := func() (string, error) {
			if req.NodeID != "" {
				// Check if it's a valid node ID
				_, err := kdcDB.GetNode(req.NodeID)
				if err != nil {
					return "", fmt.Errorf("node not found: %s", req.NodeID)
				}
				return req.NodeID, nil
			}
			if req.NodeName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetNode(req.NodeName)
				if err == nil {
					return req.NodeName, nil
				}
				// If not found by ID, try to find by name
				nodes, err := kdcDB.GetAllNodes()
				if err != nil {
					return "", err
				}
				for _, n := range nodes {
					if n.Name == req.NodeName {
						return n.ID, nil
					}
				}
				return "", fmt.Errorf("node not found: %s", req.NodeName)
			}
			return "", fmt.Errorf("node_id or node_name is required")
		}

		// Helper to resolve component ID from name or ID
		resolveComponentID := func() (string, error) {
			if req.ComponentID != "" {
				// Check if it's a valid component ID
				_, err := kdcDB.GetComponent(req.ComponentID)
				if err != nil {
					return "", fmt.Errorf("component not found: %s", req.ComponentID)
				}
				return req.ComponentID, nil
			}
			if req.ComponentName != "" {
				// First, try to find by ID (in case user passed ID as name)
				_, err := kdcDB.GetComponent(req.ComponentName)
				if err == nil {
					return req.ComponentName, nil
				}
				// If not found by ID, try to find by name
				components, err := kdcDB.GetAllComponents()
				if err != nil {
					return "", err
				}
				for _, c := range components {
					if c.Name == req.ComponentName {
						return c.ID, nil
					}
				}
				return "", fmt.Errorf("component not found: %s", req.ComponentName)
			}
			return "", fmt.Errorf("component_id or component_name is required")
		}

		switch req.Command {
		case "add":
			nodeID, err := resolveNodeID()
			if err != nil {
				log.Printf("KDC: APIKdcNodeComponent: Failed to resolve node ID: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					log.Printf("KDC: APIKdcNodeComponent: Failed to resolve component ID: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					log.Printf("KDC: APIKdcNodeComponent: Adding component %s to node %s", componentID, nodeID)
					if err := kdcDB.AddNodeComponentAssignment(nodeID, componentID, kdcConf); err != nil {
						log.Printf("KDC: APIKdcNodeComponent: Failed to add component %s to node %s: %v", componentID, nodeID, err)
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						log.Printf("KDC: APIKdcNodeComponent: Successfully added component %s to node %s", componentID, nodeID)
						resp.Msg = fmt.Sprintf("Component %s assigned to node %s", componentID, nodeID)
					}
				}
			}

		case "delete":
			nodeID, err := resolveNodeID()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				componentID, err := resolveComponentID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					if err := kdcDB.RemoveNodeComponentAssignment(nodeID, componentID, kdcConf); err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						resp.Msg = fmt.Sprintf("Component %s removed from node %s", componentID, nodeID)
					}
				}
			}

		case "list":
			// If node_id or node_name is provided, list components for that node
			// Otherwise, list all node-component assignments
			if req.NodeID != "" || req.NodeName != "" {
				nodeID, err := resolveNodeID()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					componentIDs, err := kdcDB.GetComponentsForNode(nodeID)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = err.Error()
					} else {
						// Convert to NodeComponentAssignment structs
						assignments := make([]*NodeComponentAssignment, 0, len(componentIDs))
						for _, compID := range componentIDs {
							assignments = append(assignments, &NodeComponentAssignment{
								NodeID:      nodeID,
								ComponentID: compID,
								Active:      true,
							})
						}
						resp.Assignments = assignments
					}
				}
			} else {
				// List all node-component assignments
				assignments, err := kdcDB.GetAllNodeComponentAssignments()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
				} else {
					resp.Assignments = assignments
				}
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcServiceTransaction handles service transaction endpoints
func APIKdcServiceTransaction(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcServiceTransaction handler called")
		}
		var req KdcServiceTransactionPost

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := KdcServiceTransactionResponse{
			Time: time.Now(),
		}

		switch req.Command {
		case "start":
			serviceID := req.ServiceID
			if serviceID == "" {
				if req.ServiceName == "" {
					sendJSONError(w, http.StatusBadRequest, "service_id or service_name is required for start command")
					return
				}
				// Look up by name
				services, err := kdcDB.GetAllServices()
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = err.Error()
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}
				found := false
				for _, s := range services {
					if s.Name == req.ServiceName {
						serviceID = s.ID
						found = true
						break
					}
				}
				if !found {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Service not found: %s", req.ServiceName)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
					return
				}
			}
			txID, err := kdcDB.StartServiceTransaction(serviceID, req.CreatedBy, req.Comment)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.TxID = txID
				resp.Msg = fmt.Sprintf("Transaction %s started for service %s", txID, serviceID)
			}

		case "add-component", "remove-component":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for component commands")
				return
			}
			componentID := req.ComponentID
			if componentID == "" {
				sendJSONError(w, http.StatusBadRequest, "component_id is required")
				return
			}
			var err error
			if req.Command == "add-component" {
				err = kdcDB.AddComponentToTransaction(req.TxID, componentID)
				if err == nil {
					resp.Msg = fmt.Sprintf("Component %s added to transaction %s", componentID, req.TxID)
				}
			} else {
				err = kdcDB.RemoveComponentFromTransaction(req.TxID, componentID)
				if err == nil {
					resp.Msg = fmt.Sprintf("Component %s removed from transaction %s", componentID, req.TxID)
				}
			}
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "view":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for view command")
				return
			}
			report, err := kdcDB.ViewServiceTransaction(req.TxID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.DeltaReport = report
				resp.Msg = fmt.Sprintf("Delta report computed for transaction %s", req.TxID)
			}

		case "commit":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for commit command")
				return
			}
			report, err := kdcDB.CommitServiceTransaction(req.TxID, kdcConf, req.DryRun)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.DeltaReport = report
				if req.DryRun {
					resp.Msg = fmt.Sprintf("Dry-run completed for transaction %s (no changes applied)", req.TxID)
				} else {
					resp.Msg = fmt.Sprintf("Transaction %s committed successfully", req.TxID)
				}
			}

		case "rollback":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for rollback command")
				return
			}
			if err := kdcDB.RollbackServiceTransaction(req.TxID); err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Msg = fmt.Sprintf("Transaction %s rolled back", req.TxID)
			}

		case "get", "status":
			if req.TxID == "" {
				sendJSONError(w, http.StatusBadRequest, "tx_id is required for get/status command")
				return
			}
			tx, err := kdcDB.GetServiceTransaction(req.TxID)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Transaction = tx
				resp.Msg = fmt.Sprintf("Transaction %s retrieved", req.TxID)
			}

		case "list":
			transactions, err := kdcDB.ListServiceTransactions(req.StateFilter)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				resp.Transactions = transactions
				resp.Msg = fmt.Sprintf("Found %d transaction(s)", len(transactions))
			}

		case "cleanup":
			// Cleanup expired transactions
			transactions, err := kdcDB.ListServiceTransactions("open")
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			} else {
				cleaned := 0
				now := time.Now()
				for _, tx := range transactions {
					if tx.ExpiresAt.Before(now) {
						// Mark as rolled_back
						if err := kdcDB.RollbackServiceTransaction(tx.ID); err == nil {
							cleaned++
						}
					}
				}
				resp.Msg = fmt.Sprintf("Cleaned up %d expired transaction(s)", cleaned)
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// APIKdcCatalog handles catalog zone generation endpoints
func APIKdcCatalog(kdcDB *KdcDB, kdcConf *tnm.KdcConf) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tdns.Globals.Debug {
			log.Printf("KDC: DEBUG: APIKdcCatalog handler called")
		}
		var req struct {
			Command string `json:"command"` // "generate"
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
			return
		}

		resp := map[string]interface{}{
			"time": time.Now(),
		}

		switch req.Command {
		case "generate":
			if kdcConf.CatalogZone == "" {
				resp["error"] = true
				resp["error_msg"] = "catalog_zone is not configured in KDC config file (expected under 'kdc.catalog_zone')"
			} else {
				catalogZoneName := kdcConf.CatalogZone
				if !dns.IsFqdn(catalogZoneName) {
					catalogZoneName = dns.Fqdn(catalogZoneName)
				}

				log.Printf("KDC API: Generating catalog zone: %s", catalogZoneName)
				// Get DnsEngine addresses from tdns.Conf (for API compatibility, though not used for NS records)
				dnsEngineAddresses := tdns.Conf.Listeners.Addresses
				// Call kdc.GenerateCatalogZone (KDC-specific function in tnm/kdc/catalog.go)
				zd, err := kdcDB.GenerateCatalogZone(catalogZoneName, dnsEngineAddresses)
				if err != nil {
					resp["error"] = true
					resp["error_msg"] = err.Error()
				} else {
					resp["msg"] = fmt.Sprintf("Catalog zone '%s' generated successfully", catalogZoneName)
					resp["serial"] = zd.CurrentSerial
					resp["zone_name"] = catalogZoneName
				}
			}

		default:
			sendJSONError(w, http.StatusBadRequest, fmt.Sprintf("Unknown command: %s", req.Command))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// pingHandler is the ping endpoint handler function
func SetupKdcAPIRoutes(router *mux.Router, kdcDB *KdcDB, conf interface{}, pingHandler http.HandlerFunc) {
	if kdcDB == nil {
		log.Printf("SetupKdcAPIRoutes: KDC database not initialized, skipping KDC API routes")
		return
	}

	// Extract API key and KDC config from config
	apikey := ""
	var kdcConf *tnm.KdcConf
	if configMap, ok := conf.(map[string]interface{}); ok {
		if apiServer, ok := configMap["ApiServer"].(map[string]interface{}); ok {
			if key, ok := apiServer["ApiKey"].(string); ok {
				apikey = key
			}
		}
		if kdcConfRaw, ok := configMap["KdcConf"]; ok {
			if kdcConfPtr, ok := kdcConfRaw.(*tnm.KdcConf); ok {
				kdcConf = kdcConfPtr
			} else {
				log.Printf("SetupKdcAPIRoutes: WARNING: KdcConf in config map is not *tnm.KdcConf (got %T)", kdcConfRaw)
			}
		} else {
			log.Printf("SetupKdcAPIRoutes: WARNING: KdcConf not found in config map")
		}
	} else {
		log.Printf("SetupKdcAPIRoutes: WARNING: conf is not a map[string]interface{} (got %T)", conf)
	}

	if kdcConf == nil {
		log.Printf("SetupKdcAPIRoutes: WARNING: kdcConf is nil, /kdc/config, /kdc/debug, and /kdc/service-transaction routes will NOT be registered")
	}

	// Register routes directly on the main router with full paths
	// The router passed in already has /api/v1 routes set up via SetupAPIRouter.
	// We register KDC-specific routes with the full path /api/v1/kdc/* directly on the router.
	// We use the same API key header requirement as the main /api/v1 routes.
	if apikey != "" {
		// Routes require API key header (same as main /api/v1 routes)
		router.Path("/api/v1/kdc/zone").Headers("X-API-Key", apikey).HandlerFunc(APIKdcZone(kdcDB, kdcConf)).Methods("POST")
		router.Path("/api/v1/kdc/node").Headers("X-API-Key", apikey).HandlerFunc(APIKdcNode(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/distrib").Headers("X-API-Key", apikey).HandlerFunc(APIKdcDistrib(kdcDB, kdcConf)).Methods("POST")
		router.Path("/api/v1/kdc/service").Headers("X-API-Key", apikey).HandlerFunc(APIKdcService(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/component").Headers("X-API-Key", apikey).HandlerFunc(APIKdcComponent(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/service-component").Headers("X-API-Key", apikey).HandlerFunc(APIKdcServiceComponent(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/node-component").Headers("X-API-Key", apikey).HandlerFunc(APIKdcNodeComponent(kdcDB, kdcConf)).Methods("POST")
		if kdcConf != nil {
			router.Path("/api/v1/kdc/enroll").Headers("X-API-Key", apikey).HandlerFunc(APIKdcEnrollment(kdcDB, kdcConf)).Methods("POST")
			router.Path("/api/v1/kdc/service-transaction").Headers("X-API-Key", apikey).HandlerFunc(APIKdcServiceTransaction(kdcDB, kdcConf)).Methods("POST")
			router.Path("/api/v1/kdc/config").Headers("X-API-Key", apikey).HandlerFunc(APIKdcConfig(kdcConf, conf)).Methods("POST")
			router.Path("/api/v1/kdc/debug").Headers("X-API-Key", apikey).HandlerFunc(APIKdcDebug(kdcDB, kdcConf)).Methods("POST")
			router.Path("/api/v1/kdc/operations").Headers("X-API-Key", apikey).HandlerFunc(APIKdcOperations(kdcDB, kdcConf)).Methods("POST")
		}
	} else {
		router.Path("/api/v1/kdc/zone").HandlerFunc(APIKdcZone(kdcDB, kdcConf)).Methods("POST")
		router.Path("/api/v1/kdc/node").HandlerFunc(APIKdcNode(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/distrib").HandlerFunc(APIKdcDistrib(kdcDB, kdcConf)).Methods("POST")
		router.Path("/api/v1/kdc/service").HandlerFunc(APIKdcService(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/component").HandlerFunc(APIKdcComponent(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/service-component").HandlerFunc(APIKdcServiceComponent(kdcDB)).Methods("POST")
		router.Path("/api/v1/kdc/node-component").HandlerFunc(APIKdcNodeComponent(kdcDB, kdcConf)).Methods("POST")
		if kdcConf != nil {
			router.Path("/api/v1/kdc/enroll").HandlerFunc(APIKdcEnrollment(kdcDB, kdcConf)).Methods("POST")
			router.Path("/api/v1/kdc/service-transaction").HandlerFunc(APIKdcServiceTransaction(kdcDB, kdcConf)).Methods("POST")
			router.Path("/api/v1/kdc/config").HandlerFunc(APIKdcConfig(kdcConf, conf)).Methods("POST")
			router.Path("/api/v1/kdc/debug").HandlerFunc(APIKdcDebug(kdcDB, kdcConf)).Methods("POST")
			router.Path("/api/v1/kdc/operations").HandlerFunc(APIKdcOperations(kdcDB, kdcConf)).Methods("POST")
		}
	}

	// Register catalog zone route (requires kdcConf)
	if kdcConf != nil {
		if apikey != "" {
			router.Path("/api/v1/kdc/catalog").Headers("X-API-Key", apikey).HandlerFunc(APIKdcCatalog(kdcDB, kdcConf)).Methods("POST")
		} else {
			router.Path("/api/v1/kdc/catalog").HandlerFunc(APIKdcCatalog(kdcDB, kdcConf)).Methods("POST")
		}
	}

	log.Printf("KDC API routes registered: /api/v1/ping, /api/v1/kdc/zone, /api/v1/kdc/node, /api/v1/kdc/distrib, /api/v1/kdc/service, /api/v1/kdc/component, /api/v1/kdc/service-component, /api/v1/kdc/node-component, /api/v1/kdc/enroll, /api/v1/kdc/service-transaction, /api/v1/kdc/config, /api/v1/kdc/debug, /api/v1/kdc/catalog, /api/v1/kdc/operations")
}
