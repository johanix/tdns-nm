/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CLI commands for tdns-krs management
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"time"

	"github.com/johanix/tdns-nm/tnm/krs"
	"github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

// KrsCmd removed - commands are now direct children of root in krs-cli

var KrsDnssecCmd = &cobra.Command{
	Use:   "dnssec",
	Short: "Manage received DNSSEC keys",
}

var KrsConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage node configuration",
}

var KrsQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query KDC for keys",
}

var KrsDebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug utilities for KRS",
}

var KrsDebugDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage test distributions",
	Long:  `Commands for fetching and processing distributions.`,
}

// Components command group
var KrsComponentsCmd = &cobra.Command{
	Use:   "components",
	Short: "Manage node component assignments",
}

var krsComponentsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all component IDs assigned to this node",
	Long:  `List all component IDs that this node is assigned to serve. Components are received via encrypted distributions from the KDC.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKrsRequest(api, "/krs/components", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		componentsRaw, ok := resp["components"]
		if !ok {
			fmt.Printf("Error: 'components' key not found in response\n")
			if tdns.Globals.Debug || tdns.Globals.Verbose {
				// Show the actual response for debugging
				prettyJSON, _ := json.MarshalIndent(resp, "", "  ")
				fmt.Printf("Response received:\n%s\n", string(prettyJSON))
			}
			return
		}

		components, ok := componentsRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'components' is not an array (got %T)\n", componentsRaw)
			return
		}

		if len(components) == 0 {
			fmt.Println("No components assigned to this node")
			return
		}

		// Convert to string slice and sort
		componentIDs := make([]string, 0, len(components))
		for _, comp := range components {
			if compStr, ok := comp.(string); ok {
				componentIDs = append(componentIDs, compStr)
			}
		}
		sort.Strings(componentIDs)

		// Print components
		fmt.Printf("Components assigned to this node (%d):\n", len(componentIDs))
		for _, componentID := range componentIDs {
			fmt.Printf("  - %s\n", componentID)
		}
	},
}

// Enrollment command
var KrsEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll KRS node from enrollment blob",
	Long: `Enroll a KRS node by reading an enrollment blob file, generating keypairs,
sending an enrollment UPDATE to the KDC, and creating the KRS configuration file.

This command:
1. Parses the enrollment blob file
2. Generates a JOSE keypair
3. Generates SIG(0) keypair
4. Creates and sends an encrypted enrollment UPDATE to the KDC
5. Processes the enrollment confirmation
6. Writes configuration file and key files to the config directory

The default config directory is /etc/tdns. Use --configdir to specify a different directory.

The --notify-address flag is required and specifies the IP:port address where the KDC
should send NOTIFY messages. This should match the address where the KRS DNS engine
will listen (typically the same as the DNS engine address in the generated config).

The --crypto flag is optional; the only crypto backend is 'jose', which is also the
default.

Optional flags:
  --api-address: API server address (default: 127.0.0.1:8990)
  --db-path: Database file path (default: /var/lib/tdns/krs.db)
  --log-file: Log file path (default: /var/log/tdns/tdns-krs.log)

This command does not require a config file and will skip config initialization.`,
	// Override PersistentPreRun to skip config initialization
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Only set up CLI logging, skip config and API initialization
		tdns.SetupCliLogging()
	},
	Run: func(cmd *cobra.Command, args []string) {
		packageFile, _ := cmd.Flags().GetString("package")
		if packageFile == "" {
			log.Fatalf("Error: --package flag is required")
		}

		configDir, _ := cmd.Flags().GetString("configdir")

		notifyAddress, _ := cmd.Flags().GetString("notify-address")
		if notifyAddress == "" {
			log.Fatalf("Error: --notify-address flag is required")
		}

		// Validate notify address format (IP:port)
		if _, _, err := net.SplitHostPort(notifyAddress); err != nil {
			log.Fatalf("Error: invalid notify address format '%s': %v (expected format: IP:port or hostname:port)", notifyAddress, err)
		}

		// Get crypto backend flag (optional, normalized to lowercase)
		cryptoBackend, _ := cmd.Flags().GetString("crypto")
		var err error
		cryptoBackend, err = validateCryptoBackend(cryptoBackend)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		// Get optional flags (now have defaults set in flag definitions)
		apiAddress, _ := cmd.Flags().GetString("api-address")
		dbPath, _ := cmd.Flags().GetString("db-path")
		logFile, _ := cmd.Flags().GetString("log-file")

		// Validate API address format
		if apiAddress != "" {
			if _, _, err := net.SplitHostPort(apiAddress); err != nil {
				log.Fatalf("Error: invalid API address format '%s': %v (expected format: IP:port or hostname:port)", apiAddress, err)
			}
		}

		// Verify config directory exists
		if info, err := os.Stat(configDir); err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("Error: config directory does not exist: %s", configDir)
			}
			log.Fatalf("Error: failed to stat config directory: %v", err)
		} else if !info.IsDir() {
			log.Fatalf("Error: config directory path is not a directory: %s", configDir)
		}

		// Call enrollment function from krs package
		if err := krs.RunEnroll(packageFile, configDir, notifyAddress, cryptoBackend, apiAddress, dbPath, logFile); err != nil {
			log.Fatalf("Enrollment failed: %v", err)
		}
	},
}

// Key commands
var krsKeysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all received keys",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		keysRaw, ok := resp["keys"]
		if !ok {
			fmt.Printf("Error: 'keys' key not found in response\n")
			return
		}

		keys, ok := keysRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'keys' is not an array (got %T)\n", keysRaw)
			return
		}

		if len(keys) == 0 {
			fmt.Println("No keys received")
			return
		}

		// Sort keys by zone name, then by key ID
		sort.Slice(keys, func(i, j int) bool {
			keyI, okI := keys[i].(map[string]interface{})
			keyJ, okJ := keys[j].(map[string]interface{})
			if !okI || !okJ {
				return false
			}

			zoneI := getString(keyI, "zone_name", "ZoneName")
			zoneJ := getString(keyJ, "zone_name", "ZoneName")

			// First sort by zone name
			if zoneI != zoneJ {
				return zoneI < zoneJ
			}

			// If same zone, sort by key ID
			keyIDI := getString(keyI, "key_id", "KeyID")
			keyIDJ := getString(keyJ, "key_id", "KeyID")
			return keyIDI < keyIDJ
		})

		var lines []string
		lines = append(lines, "Zone | Key ID | Type | Alg | State | Received At")
		for _, k := range keys {
			key, ok := k.(map[string]interface{})
			if !ok {
				continue
			}

			zoneID := getString(key, "zone_name", "ZoneName")
			dnskeyID := getString(key, "key_id", "KeyID")
			keyType := getString(key, "key_type", "KeyType")
			state := getString(key, "state", "State")
			receivedAtStr := getString(key, "received_at", "ReceivedAt")

			// Format date: "2025-12-19 16:55:03" (year-mo-dy hr:min:sec)
			receivedAt := formatDateTime(receivedAtStr)

			// Get algorithm
			var algStr string
			if algVal, ok := key["algorithm"]; ok {
				switch v := algVal.(type) {
				case float64:
					algNum := uint8(v)
					if algName, ok := dns.AlgorithmToString[algNum]; ok {
						algStr = algName
					} else {
						algStr = fmt.Sprintf("%d", algNum)
					}
				case string:
					algStr = v
				default:
					algStr = fmt.Sprintf("%v", v)
				}
			} else {
				algStr = "?"
			}

			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s | %s",
				zoneID, dnskeyID, keyType, algStr, state, receivedAt))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var krsKeysHashCmd = &cobra.Command{
	Use:   "hash --keyid <key-id> [--zone <zone-id>]",
	Short: "Compute SHA-256 hash of a key's private key material",
	Run: func(cmd *cobra.Command, args []string) {
		keyID := cmd.Flag("keyid").Value.String()
		zoneID := cmd.Flag("zone").Value.String()

		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}

		// Construct the full key ID: if zone is provided, use <zone>-<keyid>, otherwise use keyid as-is
		fullKeyID := keyID
		if zoneID != "" {
			// Normalize zone to FQDN
			zoneID = dns.Fqdn(zoneID)
			fullKeyID = fmt.Sprintf("%s-%s", zoneID, keyID)
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "hash",
			"key_id":  fullKeyID,
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		hash := getString(resp, "msg", "Msg")
		if hash == "" {
			log.Fatalf("Error: hash not found in response")
		}

		fmt.Printf("Key Hash (SHA-256): %s\n", hash)
	},
}

var krsKeysPurgeCmd = &cobra.Command{
	Use:   "purge [--zone <zone-name>]",
	Short: "Delete all keys in 'removed' state",
	Long:  `Delete all keys that are in the 'removed' state. If --zone is specified, only keys for that zone are purged. Otherwise, keys for all zones are purged.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Zone is optional - if provided, normalize it
		zoneName := ""
		if tdns.Globals.Zonename != "" {
			zoneName = dns.Fqdn(tdns.Globals.Zonename)
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "purge",
		}
		if zoneName != "" {
			req["zone_name"] = zoneName
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		fmt.Printf("%s\n", getString(resp, "msg", "Msg"))
	},
}

var krsDnssecDeleteCmd = &cobra.Command{
	Use:   "delete --zone <zone-name> --keyid <key-id>",
	Short: "Delete a specific received key",
	Long:  `Delete a specific DNSSEC key by zone name and key ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zone", "keyid")
		zoneName := dns.Fqdn(tdns.Globals.Zonename)
		keyID := cmd.Flag("keyid").Value.String()

		if zoneName == "" {
			log.Fatalf("Error: --zone is required")
		}
		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":   "delete",
			"zone_name": zoneName,
			"key_id":    keyID,
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		fmt.Printf("%s\n", getString(resp, "msg", "Msg"))
	},
}

var krsKeysGetCmd = &cobra.Command{
	Use:   "get --keyid <key-id>",
	Short: "Get a specific received key",
	Run: func(cmd *cobra.Command, args []string) {
		keyID := cmd.Flag("keyid").Value.String()
		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
			"key_id":  keyID,
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		keyRaw, ok := resp["key"]
		if !ok {
			fmt.Printf("Error: 'key' key not found in response\n")
			return
		}

		key, ok := keyRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("Error: 'key' is not an object (got %T)\n", keyRaw)
			return
		}

		// Pretty print the key (excluding private key)
		keyJSON, err := json.MarshalIndent(key, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling key: %v\n", err)
			return
		}
		fmt.Println(string(keyJSON))
	},
}

var krsKeysGetByZoneCmd = &cobra.Command{
	Use:   "get-by-zone --zone <zone-id>",
	Short: "Get all received keys for a zone",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-by-zone",
			"zone_id": tdns.Globals.Zonename,
		}

		resp, err := sendKrsRequest(api, "/krs/keys", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		keysRaw, ok := resp["keys"]
		if !ok {
			fmt.Printf("Error: 'keys' key not found in response\n")
			return
		}

		keys, ok := keysRaw.([]interface{})
		if !ok {
			fmt.Printf("Error: 'keys' is not an array (got %T)\n", keysRaw)
			return
		}

		if len(keys) == 0 {
			fmt.Printf("No keys received for zone %s\n", tdns.Globals.Zonename)
			return
		}

		var lines []string
		lines = append(lines, "ID | Key ID | Type | Alg | State | Received At")
		for _, k := range keys {
			key, ok := k.(map[string]interface{})
			if !ok {
				continue
			}

			keyID := getString(key, "id", "ID")
			dnskeyID := getString(key, "key_id", "KeyID")
			keyType := getString(key, "key_type", "KeyType")
			state := getString(key, "state", "State")
			receivedAt := getString(key, "received_at", "ReceivedAt")

			// Get algorithm
			var algStr string
			if algVal, ok := key["algorithm"]; ok {
				switch v := algVal.(type) {
				case float64:
					algNum := uint8(v)
					if algName, ok := dns.AlgorithmToString[algNum]; ok {
						algStr = algName
					} else {
						algStr = fmt.Sprintf("%d", algNum)
					}
				case string:
					algStr = v
				default:
					algStr = fmt.Sprintf("%v", v)
				}
			} else {
				algStr = "?"
			}

			lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s | %s",
				keyID, dnskeyID, keyType, algStr, state, receivedAt))
		}
		fmt.Println(columnize.SimpleFormat(lines))
	},
}

// Config commands
var krsConfigGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get node configuration",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
		}

		resp, err := sendKrsRequest(api, "/krs/config", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		configRaw, ok := resp["config"]
		if !ok {
			fmt.Printf("Error: 'config' key not found in response\n")
			return
		}

		config, ok := configRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("Error: 'config' is not an object (got %T)\n", configRaw)
			return
		}

		// Pretty print the config
		configJSON, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config: %v\n", err)
			return
		}
		fmt.Println(string(configJSON))
	},
}

// Query commands
var krsQueryKmreqCmd = &cobra.Command{
	Use:   "query-kmreq --distribution-id <id> --zone <zone>",
	Short: "Force a KMREQ query to KDC",
	Run: func(cmd *cobra.Command, args []string) {
		distributionID := cmd.Flag("distribution-id").Value.String()
		PrepArgs("zonename")

		if distributionID == "" {
			log.Fatalf("Error: --distribution-id is required")
		}
		if tdns.Globals.Zonename == "" {
			log.Fatalf("Error: --zone is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":         "query-kmreq",
			"distribution_id": distributionID,
			"zone_id":         tdns.Globals.Zonename,
		}

		resp, err := sendKrsRequest(api, "/krs/query", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		fmt.Printf("%s\n", getString(resp, "msg"))
	},
}

// Debug commands
var krsDebugDistribFetchCmd = &cobra.Command{
	Use:   "fetch --id <id>",
	Short: "Fetch and process a distribution from KDC",
	Long:  `Fetches a distribution by querying CHUNK records from the KDC, reassembles the chunks, and processes the content. For clear_text distributions, displays the text. For encrypted_text distributions, displays base64 transport, ciphertext, and decrypted cleartext.`,
	Run: func(cmd *cobra.Command, args []string) {
		distributionID := cmd.Flag("id").Value.String()

		if distributionID == "" {
			log.Fatalf("Error: --id is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":         "fetch-distribution",
			"distribution_id": distributionID,
		}

		resp, err := sendKrsRequest(api, "/krs/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		fmt.Printf("%s\n", getString(resp, "msg"))

		// If content is present (clear_text or encrypted_text), display it
		if content := getString(resp, "content"); content != "" {
			fmt.Printf("\n%s\n", content)
		}
	},
}

// sendKrsRequest sends a JSON POST request to the KRS API
func sendKrsRequest(api *tdns.ApiClient, endpoint string, data interface{}) (map[string]interface{}, error) {
	var result map[string]interface{}

	bytebuf := new(bytes.Buffer)
	if err := json.NewEncoder(bytebuf).Encode(data); err != nil {
		return nil, fmt.Errorf("error encoding request: %v", err)
	}

	status, buf, err := api.Post(endpoint, bytebuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error from API POST: %v", err)
	}

	// Check HTTP status code
	if status != 200 {
		// Try to unmarshal error response for better error messages
		if err := json.Unmarshal(buf, &result); err == nil {
			if errorMsg, ok := result["error_msg"].(string); ok {
				return nil, fmt.Errorf("HTTP %d: %s", status, errorMsg)
			}
		}
		// If we can't parse the error, return the raw response
		if tdns.Globals.Debug || tdns.Globals.Verbose {
			return nil, fmt.Errorf("HTTP %d: %s", status, string(buf))
		}
		return nil, fmt.Errorf("HTTP status %d", status)
	}

	if err := json.Unmarshal(buf, &result); err != nil {
		// If unmarshaling fails, show the raw response in debug/verbose mode
		if tdns.Globals.Debug || tdns.Globals.Verbose {
			return nil, fmt.Errorf("error unmarshaling response: %v (response body: %s)", err, string(buf))
		}
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	// In debug mode, show the full response
	if tdns.Globals.Debug {
		prettyJSON, _ := json.MarshalIndent(result, "", "  ")
		fmt.Printf("Response: %s\n", string(prettyJSON))
	}

	return result, nil
}

func init() {
	KrsDnssecCmd.AddCommand(krsKeysListCmd, krsKeysGetCmd, krsKeysGetByZoneCmd, krsKeysHashCmd, krsKeysPurgeCmd, krsDnssecDeleteCmd)
	KrsConfigCmd.AddCommand(krsConfigGetCmd)
	KrsQueryCmd.AddCommand(krsQueryKmreqCmd)
	KrsDebugDistribCmd.AddCommand(krsDebugDistribFetchCmd)
	KrsDebugCmd.AddCommand(KrsDebugDistribCmd)
	KrsComponentsCmd.AddCommand(krsComponentsListCmd)
	// Commands are added directly to root in main.go, not via KrsCmd

	krsKeysGetCmd.Flags().StringP("keyid", "k", "", "Key ID")
	krsKeysGetCmd.MarkFlagRequired("keyid")

	krsKeysHashCmd.Flags().StringP("keyid", "k", "", "Key ID (DNSSEC keytag)")
	krsKeysHashCmd.Flags().StringP("zone", "z", "", "Zone ID (optional, if provided constructs full ID as <zone>-<keyid>)")
	krsKeysHashCmd.MarkFlagRequired("keyid")

	krsDnssecDeleteCmd.Flags().StringP("zone", "z", "", "Zone name")
	krsDnssecDeleteCmd.Flags().StringP("keyid", "k", "", "Key ID (DNSSEC keytag)")
	krsDnssecDeleteCmd.MarkFlagRequired("zone")
	krsDnssecDeleteCmd.MarkFlagRequired("keyid")

	krsQueryKmreqCmd.Flags().String("distribution-id", "", "Distribution ID")
	krsQueryKmreqCmd.MarkFlagRequired("distribution-id")

	krsDebugDistribFetchCmd.Flags().String("id", "", "Distribution ID")
	krsDebugDistribFetchCmd.MarkFlagRequired("id")

	// Enrollment command flags
	KrsEnrollCmd.Flags().String("package", "", "Path to enrollment blob file (required)")
	KrsEnrollCmd.MarkFlagRequired("package")
	KrsEnrollCmd.Flags().String("configdir", "/etc/tdns", "Config directory")
	KrsEnrollCmd.Flags().String("notify-address", "", "Notify address (IP:port) where KDC should send NOTIFY messages (required)")
	KrsEnrollCmd.MarkFlagRequired("notify-address")
	KrsEnrollCmd.Flags().String("crypto", "", "Crypto backend to use: 'jose' (optional, the default)")
	KrsEnrollCmd.Flags().String("api-address", "127.0.0.1:8990", "API server address (IP:port)")
	KrsEnrollCmd.Flags().String("db-path", "/var/lib/tdns/krs.db", "Database file path")
	KrsEnrollCmd.Flags().String("log-file", "/var/log/tdns/tdns-krs.log", "Log file path")
}

// formatDateTime formats an ISO 8601 datetime string to "year-mo-dy hr:min:sec"
// Input format: "2025-12-19T16:55:03.508771+01:00" or similar
// Output format: "2025-12-19 16:55:03"
func formatDateTime(isoStr string) string {
	if isoStr == "" {
		return ""
	}

	// Try parsing as RFC3339 (ISO 8601)
	t, err := time.Parse(time.RFC3339, isoStr)
	if err != nil {
		// Try parsing without timezone
		t, err = time.Parse("2006-01-02T15:04:05", isoStr)
		if err != nil {
			// Try parsing with microseconds but no timezone
			t, err = time.Parse("2006-01-02T15:04:05.999999", isoStr)
			if err != nil {
				// Fallback: return as-is if we can't parse
				return isoStr
			}
		}
	}

	// Format as "year-mo-dy hr:min:sec"
	return t.Format("2006-01-02 15:04:05")
}
