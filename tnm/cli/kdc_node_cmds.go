/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC node CLI commands
 */
package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/johanix/tdns-nm/tnm/kdc"
	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Auto-register JOSE backend
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var KdcNodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage edge nodes in KDC",
}

var KdcNodeComponentCmd = &cobra.Command{
	Use:   "component",
	Short: "Manage node-component assignments",
	Long:  `Manage which components are served by which nodes`,
}

var KdcNodeEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Manage enrollment tokens and blobs",
	Long:  `Commands for managing enrollment tokens and generating enrollment blobs for node registration.`,
}

var kdcNodeAddCmd = &cobra.Command{
	Use:   "add --node <node-id> --name <node-name> --pubkey <pubkey-file>",
	Short: "Add a new edge node to KDC",
	Long:  `Add a new edge node. pubkey-file should contain the node's JOSE public key (JWK JSON; lines starting with # are ignored)`,
	Run: func(cmd *cobra.Command, args []string) {
		// Note: nodeid, nodename, pubkeyfile are persistent flags (global variables)
		// We validate them here since PrepArgs doesn't handle persistent flags yet
		if nodeid == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		if nodename == "" {
			log.Fatalf("Error: --nodename is required")
		}
		if pubkeyfile == "" {
			log.Fatalf("Error: --pubkeyfile is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Read public key file
		pubkeyData, err := os.ReadFile(pubkeyfile)
		if err != nil {
			log.Fatalf("Error reading public key file: %v", err)
		}

		// Extract key from file (skip comment lines starting with #)
		lines := strings.Split(string(pubkeyData), "\n")
		var keyLines []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				keyLines = append(keyLines, line)
			}
		}
		pubkey := []byte(strings.Join(keyLines, "\n"))

		// Validate the JWK with the JOSE backend before sending it
		joseBackend, err := crypto.GetBackend("jose")
		if err != nil {
			log.Fatalf("Error getting JOSE backend: %v", err)
		}
		if _, err := joseBackend.ParsePublicKey(pubkey); err != nil {
			log.Fatalf("Error: public key file does not contain a valid JOSE public key (JWK): %v", err)
		}

		// Normalize node ID to FQDN
		nodeIDFQDN := dns.Fqdn(nodeid)

		req := map[string]interface{}{
			"command": "add",
			"node": map[string]interface{}{
				"id":                     nodeIDFQDN,
				"name":                   nodename,
				"long_term_jose_pub_key": pubkey,
				"supported_crypto":       []string{"jose"},
				"state":                  "online",
				"comment":                "",
			},
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all edge nodes in KDC",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if nodes, ok := resp["nodes"].([]interface{}); ok {
			if len(nodes) == 0 {
				fmt.Println("No nodes configured")
				return
			}

			// Build table rows for columnize
			lines := []string{"ID | Name | Notify Address | State | Crypto | Last Contact | Comment"}
			for _, n := range nodes {
				if node, ok := n.(map[string]interface{}); ok {
					id := fmt.Sprintf("%v", node["id"])
					name := fmt.Sprintf("%v", node["name"])
					notifyAddr := ""
					if addr, ok := node["notify_address"]; ok && addr != nil {
						notifyAddr = fmt.Sprintf("%v", addr)
					}
					state := fmt.Sprintf("%v", node["state"])
					comment := fmt.Sprintf("%v", node["comment"])
					lastContact := ""
					if lc, ok := node["last_contact"]; ok && lc != nil {
						lcStr := fmt.Sprintf("%v", lc)
						// Parse and reformat the timestamp to a more readable format
						if t, err := time.Parse(time.RFC3339, lcStr); err == nil {
							lastContact = t.Format("2006-01-02 15:04:05")
						} else {
							lastContact = lcStr
						}
					}
					// Extract supported_crypto
					supportedCrypto := ""
					if crypto, ok := node["supported_crypto"]; ok && crypto != nil {
						if cryptoList, ok := crypto.([]interface{}); ok {
							var cryptoStrs []string
							for _, c := range cryptoList {
								cryptoStrs = append(cryptoStrs, fmt.Sprintf("%v", c))
							}
							supportedCrypto = strings.Join(cryptoStrs, ",")
						} else {
							supportedCrypto = fmt.Sprintf("%v", crypto)
						}
					}
					if supportedCrypto == "" {
						supportedCrypto = "(none)"
					}
					lines = append(lines, fmt.Sprintf("%s | %s | %s | %s | %s | %s | %s", id, name, notifyAddr, state, supportedCrypto, lastContact, comment))
				}
			}

			fmt.Println(columnize.SimpleFormat(lines))
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var kdcNodeGetCmd = &cobra.Command{
	Use:   "get [node-id]",
	Short: "Get node details from KDC",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get",
			"node_id": args[0],
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		if node, ok := resp["node"].(map[string]interface{}); ok {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(node)
		} else {
			fmt.Printf("Response: %+v\n", resp)
		}
	},
}

var kdcNodeUpdateCmd = &cobra.Command{
	Use:   "update --nodeid <node-id> [--name <name>] [--notify-address <address:port>] [--comment <comment>]",
	Short: "Update node details (name, notify address, comment)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid")
		updateNodeIDFQDN := cmd.Flag("nodeid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Get current node to preserve fields not being updated
		getReq := map[string]interface{}{
			"command": "get",
			"node_id": updateNodeIDFQDN,
		}
		getResp, err := sendKdcRequest(api, "/kdc/node", getReq)
		if err != nil {
			log.Fatalf("Error getting current node: %v", err)
		}
		if getResp["error"] == true {
			log.Fatalf("Error getting current node: %v", getResp["error_msg"])
		}

		nodeMap, ok := getResp["node"].(map[string]interface{})
		if !ok {
			log.Fatalf("Error: invalid node data in response")
		}

		// Update fields if provided
		updateNode := map[string]interface{}{
			"id": updateNodeIDFQDN,
		}

		// Preserve or update name
		if nameFlag := cmd.Flag("name").Value.String(); nameFlag != "" {
			updateNode["name"] = nameFlag
		} else if name, ok := nodeMap["name"]; ok {
			updateNode["name"] = name
		}

		// Preserve or update notify_address
		if notifyAddrFlag := cmd.Flag("notify-address").Value.String(); notifyAddrFlag != "" {
			updateNode["notify_address"] = notifyAddrFlag
		} else if addr, ok := nodeMap["notify_address"]; ok {
			updateNode["notify_address"] = addr
		}

		// Preserve long_term_jose_pub_key (required field)
		// JSON encodes []byte as base64 string, so we need to decode it back to []byte
		if pubkeyVal, ok := nodeMap["long_term_jose_pub_key"]; ok {
			var pubkeyBytes []byte
			if pubkeyStr, ok := pubkeyVal.(string); ok {
				// Decode base64 string back to []byte
				pubkeyBytes, err = base64.StdEncoding.DecodeString(pubkeyStr)
				if err != nil {
					log.Fatalf("Error decoding public key from response: %v", err)
				}
			} else {
				log.Fatalf("Error: public key has unexpected type: %T", pubkeyVal)
			}
			updateNode["long_term_jose_pub_key"] = pubkeyBytes
		} else {
			log.Fatalf("Error: public key not found in node data")
		}

		// Preserve supported_crypto
		if sc, ok := nodeMap["supported_crypto"]; ok {
			updateNode["supported_crypto"] = sc
		}

		// Preserve state
		if state, ok := nodeMap["state"]; ok {
			updateNode["state"] = state
		} else {
			updateNode["state"] = "online"
		}

		// Preserve or update comment
		if commentFlag := cmd.Flag("comment").Value.String(); commentFlag != "" {
			updateNode["comment"] = commentFlag
		} else if comment, ok := nodeMap["comment"]; ok {
			updateNode["comment"] = comment
		} else {
			updateNode["comment"] = ""
		}

		req := map[string]interface{}{
			"command": "update",
			"node":    updateNode,
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeSetStateCmd = &cobra.Command{
	Use:   "set-state [node-id] [state]",
	Short: "Set node state (online, offline, compromised, suspended)",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "set-state",
			"node_id": args[0],
			"state":   args[1],
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a node from KDC",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid")
		nodeid := cmd.Flag("nodeid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "delete",
			"node_id": nodeid,
		}

		resp, err := sendKdcRequest(api, "/kdc/node", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeComponentAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Assign a component to a node",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid", "cid")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Get nodeid from persistent flag (normalized by PrepArgs)
		nodeID := cmd.Flag("nodeid").Value.String()
		componentID := cmd.Flag("cid").Value.String()

		req := map[string]interface{}{
			"command":      "add",
			"node_id":      nodeID,
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/node-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeComponentDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove a component from a node",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid", "cid")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		// Get nodeid from persistent flag (normalized by PrepArgs)
		nodeID := cmd.Flag("nodeid").Value.String()
		componentID := cmd.Flag("cid").Value.String()

		req := map[string]interface{}{
			"command":      "delete",
			"node_id":      nodeID,
			"component_id": componentID,
		}

		resp, err := sendKdcRequest(api, "/kdc/node-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcNodeComponentListCmd = &cobra.Command{
	Use:   "list [--nodeid <node-id>]",
	Short: "List node-component assignments",
	Long:  `List all node-component assignments. If --nodeid is provided, shows components for that node only. Otherwise, shows all nodes and their assigned components.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		// Check if nodeid is provided (optional)
		nodeIDFlag := cmd.Flag("nodeid")
		if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
			PrepArgs(cmd, "nodeid")
			nodeID := cmd.Flag("nodeid").Value.String()
			req["node_id"] = nodeID
		}

		resp, err := sendKdcRequest(api, "/kdc/node-component", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		assignmentsRaw, ok := resp["assignments"]
		if !ok {
			if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
				fmt.Printf("Node %s has no components assigned\n", nodeIDFlag.Value.String())
			} else {
				fmt.Printf("No node-component assignments found\n")
			}
			return
		}

		assignments, ok := assignmentsRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: 'assignments' is not an array")
		}

		if len(assignments) == 0 {
			if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
				fmt.Printf("Node %s has no components assigned\n", nodeIDFlag.Value.String())
			} else {
				fmt.Printf("No node-component assignments found\n")
			}
			return
		}

		// Group assignments by node
		nodeAssignments := make(map[string][]string)
		for _, a := range assignments {
			assignment, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			nodeID := getString(assignment, "node_id")
			componentID := getString(assignment, "component_id")
			if nodeID != "" && componentID != "" {
				nodeAssignments[nodeID] = append(nodeAssignments[nodeID], componentID)
			}
		}

		if nodeIDFlag != nil && nodeIDFlag.Value.String() != "" {
			// Single node: show detailed component list
			nodeID := nodeIDFlag.Value.String()
			fmt.Printf("Components for node %s:\n", nodeID)

			// Build table rows for columnize
			var rows []string
			rows = append(rows, "Component ID | Active")

			for _, a := range assignments {
				assignment, ok := a.(map[string]interface{})
				if !ok {
					continue
				}
				componentID := getString(assignment, "component_id")
				active := getBool(assignment, "active")
				activeStr := "yes"
				if !active {
					activeStr = "no"
				}
				rows = append(rows, fmt.Sprintf("%s | %s", componentID, activeStr))
			}

			if len(rows) > 1 {
				fmt.Println(columnize.SimpleFormat(rows))
			}
		} else {
			// All nodes: show one line per node with components
			// Build table rows for columnize
			var rows []string
			rows = append(rows, "Node ID | Components")

			// Sort nodes for consistent output
			var nodeIDs []string
			for nodeID := range nodeAssignments {
				nodeIDs = append(nodeIDs, nodeID)
			}
			sort.Strings(nodeIDs)

			for _, nodeID := range nodeIDs {
				components := nodeAssignments[nodeID]
				componentsStr := strings.Join(components, ", ")
				if componentsStr == "" {
					componentsStr = "(none)"
				}
				rows = append(rows, fmt.Sprintf("%s | %s", nodeID, componentsStr))
			}

			if len(rows) > 1 {
				fmt.Println(columnize.SimpleFormat(rows))
			}
		}
	},
}

var kdcNodeEnrollGenerateCmd = &cobra.Command{
	Use:   "generate --nodeid <nodeid> --outdir <directory> [--comment <comment>]",
	Short: "Generate an enrollment token and blob file",
	Long: `Generate an enrollment token for a node and create an enrollment blob file.
The enrollment blob contains the token, node ID, KDC JOSE public key, enrollment address, and control zone.
The blob is base64-encoded JSON written to {nodeid}.enroll file in the specified output directory.
The output directory must exist.`,
	Run: func(cmd *cobra.Command, args []string) {
		nodeID, _ := cmd.Flags().GetString("nodeid")
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		// Ensure node ID is FQDN
		nodeID = dns.Fqdn(nodeID)

		outDir, _ := cmd.Flags().GetString("outdir")
		if outDir == "" {
			log.Fatalf("Error: --outdir is required")
		}

		// Verify output directory exists
		info, err := os.Stat(outDir)
		if err != nil {
			log.Fatalf("Error: Output directory does not exist or is not accessible: %v", err)
		}
		if !info.IsDir() {
			log.Fatalf("Error: Output path is not a directory: %s", outDir)
		}

		comment, _ := cmd.Flags().GetString("comment")
		cryptoBackend, _ := cmd.Flags().GetString("crypto")

		// Validate crypto backend if provided (normalized to lowercase)
		cryptoBackend, err = validateCryptoBackend(cryptoBackend)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		// Call API (with fallback to DB)
		// Note: outdir is not sent to API - CLI writes the file locally
		req := map[string]interface{}{
			"command": "generate",
			"node_id": nodeID,
		}
		if comment != "" {
			req["comment"] = comment
		}
		if cryptoBackend != "" {
			req["crypto"] = cryptoBackend
		}

		resp, err := callEnrollAPI("generate", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		// Extract token from response
		tokenRaw, ok := resp["token"]
		if !ok {
			log.Fatalf("Error: No token in response")
		}

		// Convert token to EnrollmentToken struct
		tokenJSON, _ := json.Marshal(tokenRaw)
		var token kdc.EnrollmentToken
		if err := json.Unmarshal(tokenJSON, &token); err != nil {
			log.Fatalf("Error parsing token: %v", err)
		}

		// Extract blob content and write to file
		blobContent := getString(resp, "blob_content")
		if blobContent == "" {
			// Fallback to old blob_path for backward compatibility
			blobPath := getString(resp, "blob_path")
			if blobPath != "" {
				fmt.Printf("Enrollment token generated for node: %s\n", nodeID)
				fmt.Printf("Token ID: %s\n", token.TokenID)
				fmt.Printf("Enrollment blob written to: %s\n", blobPath)
				return
			}
			log.Fatalf("Error: No blob content in response")
		}

		// Write blob file to specified directory with comment header
		// Remove trailing dot from FQDN for filename
		nodeIDForFile := strings.TrimSuffix(nodeID, ".")
		filename := filepath.Join(outDir, fmt.Sprintf("%s.enroll", nodeIDForFile))
		var fileContent []byte
		// Add comment line with timestamp
		generatedAt := time.Now().Format("2006-01-02 15:04:05")
		commentLine := fmt.Sprintf("# enrollment package for node \"%s\" generated at %s\n", nodeID, generatedAt)
		fileContent = append(fileContent, []byte(commentLine)...)
		// Add base64 content
		fileContent = append(fileContent, []byte(blobContent)...)
		fileContent = append(fileContent, '\n') // Add newline at end
		if err := os.WriteFile(filename, fileContent, 0644); err != nil {
			log.Fatalf("Error writing enrollment blob file: %v", err)
		}

		// Get absolute path for display
		absPath, err := filepath.Abs(filename)
		if err != nil {
			absPath = filename
		}

		fmt.Printf("Enrollment token generated for node: %s\n", nodeID)
		fmt.Printf("Token ID: %s\n", token.TokenID)
		fmt.Printf("Enrollment blob written to: %s\n", absPath)
	},
}

var kdcNodeEnrollActivateCmd = &cobra.Command{
	Use:   "activate --nodeid <nodeid> [--expiration <duration>]",
	Short: "Activate an enrollment token",
	Long: `Activate an enrollment token for a node. This sets the activation timestamp and expiration time.
The expiration window defaults to 5 minutes if not specified.`,
	Run: func(cmd *cobra.Command, args []string) {
		nodeID, _ := cmd.Flags().GetString("nodeid")
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		// Ensure node ID is FQDN
		nodeID = dns.Fqdn(nodeID)

		expirationStr, _ := cmd.Flags().GetString("expiration")
		if expirationStr == "" {
			expirationStr = "5m" // Default
		}

		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command":           "activate",
			"node_id":           nodeID,
			"expiration_window": expirationStr,
		}

		resp, err := callEnrollAPI("activate", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		fmt.Printf("Enrollment token activated for node: %s\n", nodeID)
		fmt.Printf("Expiration window: %s\n", expirationStr)
	},
}

var kdcNodeEnrollListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all enrollment tokens",
	Long:  `List all enrollment tokens with their status, node ID, creation time, and expiration time.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := callEnrollAPI("list", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		// Extract tokens from response
		tokensRaw, ok := resp["tokens"]
		if !ok {
			fmt.Println("No enrollment tokens found")
			return
		}

		tokensArray, ok := tokensRaw.([]interface{})
		if !ok {
			log.Fatalf("Error: Invalid tokens format in response")
		}

		if len(tokensArray) == 0 {
			fmt.Println("No enrollment tokens found")
			return
		}

		// Convert to EnrollmentToken structs
		var tokens []*kdc.EnrollmentToken
		for _, tokenRaw := range tokensArray {
			tokenJSON, _ := json.Marshal(tokenRaw)
			var token kdc.EnrollmentToken
			if err := json.Unmarshal(tokenJSON, &token); err == nil {
				tokens = append(tokens, &token)
			}
		}

		// Display tokens in a table (similar to dnssec key listing)
		var lines []string
		lines = append(lines, "Node ID | Token ID | Status | Timestamp | Event")

		for _, token := range tokens {
			// Calculate status from token fields
			var status string
			if token.Used {
				status = "completed"
			} else if !token.Activated {
				status = "generated"
			} else if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
				status = "expired"
			} else {
				status = "active"
			}

			// Determine timestamp and event based on current state
			var timestamp, event string
			if token.Used && token.UsedAt != nil {
				// Token was used - show when it was used
				timestamp = token.UsedAt.Format("2006-01-02 15:04:05")
				event = "enrollment completed"
			} else if status == "expired" && token.ExpiresAt != nil {
				// Token expired - show expiration time
				timestamp = token.ExpiresAt.Format("2006-01-02 15:04:05")
				event = "expired"
			} else if token.Activated && token.ActivatedAt != nil {
				// Token is active - show when it was activated and expiration time
				timestamp = token.ActivatedAt.Format("2006-01-02 15:04:05")
				if token.ExpiresAt != nil {
					expiresStr := token.ExpiresAt.Format("2006-01-02 15:04:05")
					event = fmt.Sprintf("activated (expires at %s)", expiresStr)
				} else {
					event = "activated"
				}
			} else {
				// Token is generated but not activated - show creation time
				timestamp = token.CreatedAt.Format("2006-01-02 15:04:05")
				event = "generated enrollment package"
			}

			tokenIDDisplay := token.TokenID
			if len(tokenIDDisplay) > 8 {
				tokenIDDisplay = tokenIDDisplay[:8] + "..."
			}

			line := fmt.Sprintf("%s | %s | %s | %s | %s",
				token.NodeID, tokenIDDisplay, status, timestamp, event)
			lines = append(lines, line)
		}

		fmt.Println(columnize.SimpleFormat(lines))
	},
}

var kdcNodeEnrollPurgeCmd = &cobra.Command{
	Use:   "purge [--files]",
	Short: "Purge expired and completed enrollment tokens",
	Long: `Delete enrollment tokens with status "expired" or "completed".
Use --files to also delete associated enrollment blob files.`,
	Run: func(cmd *cobra.Command, args []string) {
		deleteFiles, _ := cmd.Flags().GetBool("files")

		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command":      "purge",
			"delete_files": deleteFiles,
		}

		resp, err := callEnrollAPI("purge", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		msg := getString(resp, "msg")
		if msg != "" {
			fmt.Printf("%s\n", msg)
		} else {
			count := getInt(resp, "count")
			fmt.Printf("Purged %d enrollment token(s)\n", count)
		}
	},
}

var kdcNodeEnrollStatusCmd = &cobra.Command{
	Use:   "status --nodeid <nodeid>",
	Short: "Show detailed status of an enrollment token",
	Long:  `Show detailed status information for a specific enrollment token.`,
	Run: func(cmd *cobra.Command, args []string) {
		nodeID, _ := cmd.Flags().GetString("nodeid")
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}
		// Ensure node ID is FQDN
		nodeID = dns.Fqdn(nodeID)

		// Call API (with fallback to DB)
		req := map[string]interface{}{
			"command": "status",
			"node_id": nodeID,
		}

		resp, err := callEnrollAPI("status", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if getBool(resp, "error") {
			log.Fatalf("Error: %v", getString(resp, "error_msg"))
		}

		status := getString(resp, "status")
		if status == "not_found" {
			fmt.Printf("No enrollment token found for node: %s\n", nodeID)
			return
		}

		// Extract token from response
		tokenRaw, ok := resp["token"]
		if !ok {
			fmt.Printf("Enrollment Token Status for Node: %s\n", nodeID)
			fmt.Printf("  Status: %s\n", status)
			return
		}

		// Convert token to EnrollmentToken struct
		tokenJSON, _ := json.Marshal(tokenRaw)
		var token kdc.EnrollmentToken
		if err := json.Unmarshal(tokenJSON, &token); err != nil {
			log.Fatalf("Error parsing token: %v", err)
		}

		// Display detailed status
		fmt.Printf("Enrollment Token Status for Node: %s\n", nodeID)
		fmt.Printf("  Status: %s\n", status)
		fmt.Printf("  Token ID: %s\n", token.TokenID)
		fmt.Printf("  Created: %s\n", token.CreatedAt.Format(time.RFC3339))
		if token.ActivatedAt != nil {
			fmt.Printf("  Activated: %s\n", token.ActivatedAt.Format(time.RFC3339))
		}
		if token.ExpiresAt != nil {
			fmt.Printf("  Expires: %s\n", token.ExpiresAt.Format(time.RFC3339))
			if time.Now().After(*token.ExpiresAt) {
				fmt.Printf("  Expired: Yes\n")
			} else {
				remaining := time.Until(*token.ExpiresAt)
				fmt.Printf("  Time remaining: %s\n", remaining)
			}
		}
		fmt.Printf("  Used: %v\n", token.Used)
		if token.UsedAt != nil {
			fmt.Printf("  Used at: %s\n", token.UsedAt.Format(time.RFC3339))
		}
		if token.Comment != "" {
			fmt.Printf("  Comment: %s\n", token.Comment)
		}
	},
}

var kdcNodePingCmd = &cobra.Command{
	Use:   "ping [--nodeid <node-id> | --all]",
	Short: "Send ping operation to node(s)",
	Long: `Send a ping operation to one or all edge nodes.
The ping operation validates the cryptographic pipeline and confirms node connectivity.
Either --nodeid or --all must be specified.`,
	Run: func(cmd *cobra.Command, args []string) {
		all, _ := cmd.Flags().GetBool("all")
		nodeIDFlag, _ := cmd.Flags().GetString("nodeid")

		if !all && nodeIDFlag == "" {
			log.Fatalf("Error: Either --nodeid or --all must be specified")
		}
		if all && nodeIDFlag != "" {
			log.Fatalf("Error: Cannot specify both --nodeid and --all")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "ping",
		}

		if all {
			req["all"] = true
		} else {
			// Normalize node ID to FQDN
			nodeID := dns.Fqdn(nodeIDFlag)
			req["node_id"] = nodeID
		}

		// Add crypto flag if specified (normalized to lowercase)
		cryptoBackend, _ := cmd.Flags().GetString("crypto")
		if cryptoBackend != "" {
			var err error
			cryptoBackend, err = validateCryptoBackend(cryptoBackend)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			req["crypto"] = cryptoBackend
		}

		resp, err := sendKdcRequest(api, "/kdc/operations", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])

		// Show distribution IDs if provided
		if distIDs, ok := resp["distribution_ids"].([]interface{}); ok && len(distIDs) > 0 {
			fmt.Printf("Distribution IDs: ")
			for i, id := range distIDs {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%v", id)
			}
			fmt.Printf("\n")
		}
	},
}

func init() {
	KdcNodeComponentCmd.AddCommand(kdcNodeComponentAddCmd, kdcNodeComponentDeleteCmd, kdcNodeComponentListCmd)
	KdcNodeEnrollCmd.AddCommand(kdcNodeEnrollGenerateCmd, kdcNodeEnrollActivateCmd, kdcNodeEnrollListCmd, kdcNodeEnrollPurgeCmd, kdcNodeEnrollStatusCmd)
	KdcNodeCmd.AddCommand(kdcNodeAddCmd, kdcNodeListCmd, kdcNodeGetCmd, kdcNodeUpdateCmd, kdcNodeSetStateCmd, kdcNodeDeleteCmd, kdcNodePingCmd, KdcNodeComponentCmd, KdcNodeEnrollCmd)

	// Node-component command flags
	kdcNodeComponentAddCmd.Flags().StringP("cid", "c", "", "Component ID")
	kdcNodeComponentAddCmd.MarkFlagRequired("cid")
	kdcNodeComponentDeleteCmd.Flags().StringP("cid", "c", "", "Component ID")
	kdcNodeComponentDeleteCmd.MarkFlagRequired("cid")
	// kdcNodeComponentListCmd uses persistent nodeid flag, no additional flags needed

	KdcNodeCmd.PersistentFlags().StringVarP(&nodeid, "nodeid", "n", "", "node id")
	KdcNodeCmd.PersistentFlags().StringVarP(&nodename, "nodename", "N", "", "node name")
	KdcNodeCmd.PersistentFlags().StringVarP(&pubkeyfile, "pubkeyfile", "p", "", "public key file")

	kdcNodeUpdateCmd.Flags().StringP("nodeid", "n", "", "Node ID (required)")
	kdcNodeUpdateCmd.MarkFlagRequired("nodeid")
	kdcNodeUpdateCmd.Flags().StringP("name", "", "", "Node name")
	kdcNodeUpdateCmd.Flags().StringP("notify-address", "a", "", "Notify address:port (e.g., 192.0.2.1:53)")
	kdcNodeUpdateCmd.Flags().StringP("comment", "c", "", "Comment")

	kdcNodeEnrollGenerateCmd.Flags().String("nodeid", "", "Node ID")
	kdcNodeEnrollGenerateCmd.MarkFlagRequired("nodeid")
	kdcNodeEnrollGenerateCmd.Flags().String("outdir", "", "Output directory (must exist)")
	kdcNodeEnrollGenerateCmd.MarkFlagRequired("outdir")
	kdcNodeEnrollGenerateCmd.Flags().String("comment", "", "Optional comment")
	kdcNodeEnrollGenerateCmd.Flags().String("crypto", "", "Crypto backend to use (jose, the default).")

	kdcNodeEnrollActivateCmd.Flags().String("nodeid", "", "Node ID")
	kdcNodeEnrollActivateCmd.MarkFlagRequired("nodeid")
	kdcNodeEnrollActivateCmd.Flags().String("expiration", "", "Expiration window (e.g., 5m, 1h)")

	kdcNodeEnrollPurgeCmd.Flags().Bool("files", false, "Also delete enrollment blob files")

	kdcNodeEnrollStatusCmd.Flags().String("nodeid", "", "Node ID")
	kdcNodeEnrollStatusCmd.MarkFlagRequired("nodeid")

	kdcNodePingCmd.Flags().String("nodeid", "", "Node ID to ping")
	kdcNodePingCmd.Flags().Bool("all", false, "Ping all active nodes")
	kdcNodePingCmd.Flags().String("crypto", "", "Force crypto backend (jose). If not specified, uses any backend the node supports.")
}
