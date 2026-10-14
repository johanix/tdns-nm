/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Common utilities and shared code for KDC CLI commands
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-nm/tnm/kdc"
	tdns "github.com/johanix/tdns/v2"
	"gopkg.in/yaml.v3"
)

// validateCryptoBackend validates that a crypto backend string is either empty or "jose"
// Normalizes input to lowercase for better UX (e.g., "JOSE" -> "jose")
// Returns the normalized value and an error if the value is invalid, or nil error if valid
func validateCryptoBackend(crypto string) (string, error) {
	if crypto == "" {
		return "", nil
	}
	// Normalize to lowercase for better UX
	normalized := strings.ToLower(crypto)
	if normalized != "jose" {
		return "", fmt.Errorf("--crypto must be 'jose' (got: %s)", crypto)
	}
	return normalized, nil
}

// Shared variables for node commands
var nodeid, nodename, pubkeyfile string

// sendKdcRequest sends a JSON POST request to the KDC API
func sendKdcRequest(api *tdns.ApiClient, endpoint string, data interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}

	bytebuf := new(bytes.Buffer)
	if err := json.NewEncoder(bytebuf).Encode(data); err != nil {
		return nil, fmt.Errorf("error encoding request: %v", err)
	}

	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "DEBUG: Sending POST request to %s\n", endpoint)
		reqJSON, _ := json.MarshalIndent(data, "", "  ")
		fmt.Fprintf(os.Stderr, "DEBUG: Request body: %s\n", reqJSON)
	}

	status, buf, err := api.Post(endpoint, bytebuf.Bytes())
	if err != nil {
		if tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "DEBUG: API POST error: %v\n", err)
		}
		return nil, fmt.Errorf("error from API POST: %v", err)
	}

	// Only print status if it's not 200 (success) - useful for debugging errors
	if status != 200 {
		if tdns.Globals.Verbose || tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "DEBUG: API returned status: %d\n", status)
			if tdns.Globals.Debug {
				fmt.Fprintf(os.Stderr, "DEBUG: Response body: %s\n", string(buf))
			}
		}
	}

	if err := json.Unmarshal(buf, &result); err != nil {
		if tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "DEBUG: JSON decode error: %v\n", err)
			fmt.Fprintf(os.Stderr, "DEBUG: Response body: %s\n", string(buf))
		}
		fmt.Printf("Request: URL: %s, Body: %s\n", endpoint, bytebuf.String())
		fmt.Printf("Response causing error: %s\n", string(buf))
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "DEBUG: API response decoded successfully\n")
	}

	return result, nil
}

// Helper functions for extracting values from JSON maps
func getString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func getBool(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch val := v.(type) {
			case bool:
				return val
			case string:
				return val == "true" || val == "1"
			case float64:
				return val != 0
			case int:
				return val != 0
			}
		}
	}
	return false
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return 0
}

// Helper function to get KDC config file path from CLI config
func getKdcConfigPath() (string, error) {
	clientKey := getClientKey()
	if clientKey == "" {
		return "", fmt.Errorf("no client key set")
	}

	// Get API details for this client
	apiDetails := getApiDetailsByClientKey(clientKey)
	if apiDetails == nil {
		return "", fmt.Errorf("API details not found for %s", clientKey)
	}

	var configPath string
	var source string

	// Check if config path is specified
	if path, ok := apiDetails["config"].(string); ok && path != "" {
		configPath = path
		source = "CLI config"
	} else {
		// Fallback: try default KDC config file location
		defaultPath := tdns.DefaultKdcCfgFile
		if _, err := os.Stat(defaultPath); err == nil {
			configPath = defaultPath
			source = "default location"
		} else {
			return "", fmt.Errorf("KDC config file not specified in CLI config and default path %s not found", defaultPath)
		}
	}

	// Log config file usage in debug mode
	if tdns.Globals.Debug || tdns.Globals.Verbose {
		fmt.Fprintf(os.Stderr, "Using KDC config file (%s): %s\n", source, configPath)
	}

	return configPath, nil
}

// Helper function to load KDC config from file
func loadKdcConfigFromFile(configPath string) (*tnm.KdcConf, error) {
	// Read config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read KDC config file %s: %v", configPath, err)
	}

	// The KDC config file has the kdc section nested, so we need to unmarshal into a wrapper
	type KdcConfigWrapper struct {
		Kdc tnm.KdcConf `yaml:"kdc"`
	}

	var wrapper KdcConfigWrapper
	if err := yaml.Unmarshal(configData, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KDC config: %v", err)
	}

	kdcConf := wrapper.Kdc

	// Validate that database config is present
	if kdcConf.Database.Type == "" {
		return nil, fmt.Errorf("database type not specified in KDC config file %s (expected under 'kdc.database.type')", configPath)
	}
	if kdcConf.Database.DSN == "" {
		return nil, fmt.Errorf("database DSN not specified in KDC config file %s (expected under 'kdc.database.dsn')", configPath)
	}

	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "KDC config loaded: database type=%s, control_zone=%s\n",
			kdcConf.Database.Type, kdcConf.ControlZone)
	}

	return &kdcConf, nil
}

// Helper function to get KDC config from file
func getKdcConfig() (*tnm.KdcConf, error) {
	// Get config file path
	configPath, err := getKdcConfigPath()
	if err != nil {
		return nil, err
	}

	// Load KDC config from file
	return loadKdcConfigFromFile(configPath)
}

// Helper function to call enrollment API with fallback to direct DB access
func callEnrollAPI(command string, reqData map[string]interface{}) (map[string]interface{}, error) {
	// Try API first
	api, err := getApiClient(false) // Don't die on error, we'll fallback
	if err == nil && api != nil {
		if tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "Attempting enrollment API call: %s\n", command)
		}
		resp, err := sendKdcRequest(api, "/kdc/enroll", reqData)
		if err == nil {
			if tdns.Globals.Debug {
				fmt.Fprintf(os.Stderr, "Enrollment API call successful\n")
			}
			return resp, nil
		}
		// API failed, fallback to direct DB
		if tdns.Globals.Verbose || tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "Warning: API call failed (%v), falling back to direct database access\n", err)
		}
	} else {
		if tdns.Globals.Verbose || tdns.Globals.Debug {
			fmt.Fprintf(os.Stderr, "Warning: API client unavailable (%v), using direct database access\n", err)
		}
	}

	// Fallback: direct database access
	if tdns.Globals.Debug {
		fmt.Fprintf(os.Stderr, "Using direct database access for enrollment operation: %s\n", command)
	}
	return callEnrollDB(command, reqData)
}

// Helper function to call enrollment operations via direct database access
func callEnrollDB(command string, reqData map[string]interface{}) (map[string]interface{}, error) {
	// Get KDC config path and load config (for debug output)
	configPath, err := getKdcConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get KDC config path: %v", err)
	}

	// Load KDC config from file
	kdcConf, err := loadKdcConfigFromFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load KDC config: %v", err)
	}

	// Create database connection
	kdcDB, err := kdc.NewKdcDB(kdcConf.Database.Type, kdcConf.Database.DSN, kdcConf)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}
	defer kdcDB.DB.Close()

	result := make(map[string]interface{})
	result["time"] = time.Now()

	switch command {
	case "generate":
		nodeID, _ := reqData["node_id"].(string)
		if nodeID == "" {
			result["error"] = true
			result["error_msg"] = "node_id is required"
			return result, nil
		}

		// Check if node already exists and is active
		existingNode, err := kdcDB.GetNode(nodeID)
		if err == nil {
			// Node exists - check if it's in an active state
			if existingNode.State == kdc.NodeStateOnline {
				result["error"] = true
				result["error_msg"] = fmt.Sprintf("Node %s already exists and is online. Cannot generate enrollment blob for an active node. Delete the node first (kdc-cli node delete --nodeid %s) or set it to a non-active state (suspended/offline) before re-enrolling.", nodeID, nodeID)
				return result, nil
			}
			// Node exists but is not online (offline, suspended, compromised) - allow re-enrollment
			// This is intentional - nodes in these states may need to re-enroll
		}
		// If node doesn't exist (err != nil), that's fine - it's a new node

		// Check if token already exists
		status, err := kdcDB.GetEnrollmentTokenStatus(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		if status != "not_found" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Enrollment token already exists for node %s (status: %s)", nodeID, status)
			return result, nil
		}

		// Generate token
		token, err := kdcDB.GenerateEnrollmentToken(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}

		result["token"] = token
		result["msg"] = fmt.Sprintf("Enrollment token generated for node: %s", nodeID)

		// Generate enrollment blob content (CLI will write the file)
		kdcConf, err := getKdcConfig()
		if err != nil {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Failed to load KDC config: %v", err)
			return result, nil
		}

		// Get crypto backend from request (optional)
		cryptoBackend, _ := reqData["crypto"].(string)

		blobContent, err := kdc.GenerateEnrollmentBlobContent(nodeID, token, kdcConf, cryptoBackend)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}

		result["blob_content"] = blobContent

	case "activate":
		nodeID, _ := reqData["node_id"].(string)
		if nodeID == "" {
			result["error"] = true
			result["error_msg"] = "node_id is required"
			return result, nil
		}

		expirationStr, _ := reqData["expiration_window"].(string)
		expirationWindow := 5 * time.Minute
		if expirationStr != "" {
			var err error
			expirationWindow, err = time.ParseDuration(expirationStr)
			if err != nil {
				result["error"] = true
				result["error_msg"] = fmt.Sprintf("Invalid expiration_window format: %v", err)
				return result, nil
			}
		}

		// Check token status
		status, err := kdcDB.GetEnrollmentTokenStatus(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		if status == "not_found" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("No enrollment token found for node %s", nodeID)
			return result, nil
		}
		if status == "active" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Enrollment token for node %s is already activated", nodeID)
			return result, nil
		}
		if status == "completed" {
			result["error"] = true
			result["error_msg"] = fmt.Sprintf("Enrollment token for node %s has already been used", nodeID)
			return result, nil
		}

		err = kdcDB.ActivateEnrollmentToken(nodeID, expirationWindow)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}

		result["msg"] = fmt.Sprintf("Enrollment token activated for node: %s", nodeID)

	case "list":
		tokens, err := kdcDB.ListEnrollmentTokens()
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}
		result["tokens"] = tokens
		result["msg"] = fmt.Sprintf("Found %d enrollment token(s)", len(tokens))

	case "status":
		nodeID, _ := reqData["node_id"].(string)
		if nodeID == "" {
			result["error"] = true
			result["error_msg"] = "node_id is required"
			return result, nil
		}

		status, err := kdcDB.GetEnrollmentTokenStatus(nodeID)
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}

		result["status"] = status
		if status != "not_found" {
			tokens, err := kdcDB.ListEnrollmentTokens()
			if err == nil {
				for _, t := range tokens {
					if t.NodeID == nodeID {
						result["token"] = t
						break
					}
				}
			}
		}

	case "purge":
		deleteFiles, _ := reqData["delete_files"].(bool)
		count, err := kdcDB.PurgeEnrollmentTokens()
		if err != nil {
			result["error"] = true
			result["error_msg"] = err.Error()
			return result, nil
		}

		result["count"] = count
		result["msg"] = fmt.Sprintf("Purged %d enrollment token(s)", count)

		if deleteFiles && count > 0 {
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
				result["msg"] = fmt.Sprintf("%s, deleted %d blob file(s)", result["msg"], deletedFiles)
			}
		}

	default:
		result["error"] = true
		result["error_msg"] = fmt.Sprintf("Unknown command: %s", command)
		return result, nil
	}

	return result, nil
}
