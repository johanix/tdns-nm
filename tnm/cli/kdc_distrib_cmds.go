/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC distribution CLI commands
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var KdcDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage key distributions",
	Long:  `Commands for managing key distributions, including listing distributions, checking their state, marking them as completed, and distributing keys to edge nodes.`,
}

var kdcDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all ongoing distributions",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list",
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])

		// Check for verbose flag
		verbose := false
		if v, err := cmd.Flags().GetBool("verbose"); err == nil {
			verbose = v
		}

		// Try to get summaries (new format)
		if summariesRaw, ok := resp["summaries"].([]interface{}); ok && len(summariesRaw) > 0 {
			if verbose {
				// Verbose mode: show full multiline information
				fmt.Println("\nDistributions:")
				for _, sRaw := range summariesRaw {
					if s, ok := sRaw.(map[string]interface{}); ok {
						distID := getString(s, "distribution_id")
						fmt.Printf("\n  Distribution ID: %s\n", distID)

						// Show operations
						if operations, ok := s["operations"].([]interface{}); ok && len(operations) > 0 {
							opStrs := make([]string, len(operations))
							for i, op := range operations {
								opStrs[i] = fmt.Sprintf("%v", op)
							}
							fmt.Printf("    Operation: %s\n", strings.Join(opStrs, ", "))
						}

						if nodes, ok := s["nodes"].([]interface{}); ok {
							nodeStrs := make([]string, len(nodes))
							for i, n := range nodes {
								nodeStrs[i] = fmt.Sprintf("%v", n)
							}
							fmt.Printf("    Nodes: %s\n", strings.Join(nodeStrs, ", "))
						}

						if zones, ok := s["zones"].([]interface{}); ok {
							zoneStrs := make([]string, len(zones))
							for i, z := range zones {
								zoneStrs[i] = fmt.Sprintf("%v", z)
							}
							fmt.Printf("    Zones: %s\n", strings.Join(zoneStrs, ", "))
						}

						zskCount := 0
						if z, ok := s["zsk_count"].(float64); ok {
							zskCount = int(z)
						}
						kskCount := 0
						if k, ok := s["ksk_count"].(float64); ok {
							kskCount = int(k)
						}
						fmt.Printf("    Keys: %d ZSK, %d KSK\n", zskCount, kskCount)

						if keys, ok := s["keys"].(map[string]interface{}); ok {
							fmt.Printf("    Key Details:\n")
							for zone, keyID := range keys {
								fmt.Printf("      %s: key %v\n", zone, keyID)
							}
						}

						if completedAt, ok := s["completed_at"].(string); ok && completedAt != "" {
							// Parse and format the datetime nicely
							if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
								fmt.Printf("    Completed: %s\n", t.Format("2006-01-02 15:04:05"))
							} else {
								fmt.Printf("    Completed: %s\n", completedAt)
							}
						} else {
							allConfirmed := false
							if a, ok := s["all_confirmed"].(bool); ok {
								allConfirmed = a
							}
							if allConfirmed {
								fmt.Printf("    Status: All nodes confirmed\n")
							} else {
								// Show confirmed and pending nodes
								confirmedNodes := []string{}
								if c, ok := s["confirmed_nodes"].([]interface{}); ok {
									for _, n := range c {
										confirmedNodes = append(confirmedNodes, fmt.Sprintf("%v", n))
									}
								}
								pendingNodes := []string{}
								if p, ok := s["pending_nodes"].([]interface{}); ok {
									for _, n := range p {
										pendingNodes = append(pendingNodes, fmt.Sprintf("%v", n))
									}
								}

								if len(confirmedNodes) > 0 {
									fmt.Printf("    Confirmed nodes: %s\n", strings.Join(confirmedNodes, ", "))
								}
								if len(pendingNodes) > 0 {
									fmt.Printf("    Pending nodes: %s\n", strings.Join(pendingNodes, ", "))
								} else {
									fmt.Printf("    Status: Pending confirmations\n")
								}
							}
						}
					}
				}
			} else {
				// Default mode: show tabular format
				// Get control zone from config for building QNAMEs
				controlZone := "kdc." // Default
				configResp, configErr := sendKdcRequest(api, "/kdc/config", map[string]interface{}{"command": "get"})
				if configErr == nil {
					if config, ok := configResp["config"].(map[string]interface{}); ok {
						if cz, ok := config["control_zone"].(string); ok && cz != "" {
							controlZone = cz
							if !strings.HasSuffix(controlZone, ".") {
								controlZone = controlZone + "."
							}
						}
					}
				}

				var rows []string
				rows = append(rows, "Id | State | Time | Node | Contents | Query")

				for _, sRaw := range summariesRaw {
					if s, ok := sRaw.(map[string]interface{}); ok {
						distID := getString(s, "distribution_id")
						if distID == "" {
							continue
						}

						// Get node
						nodeStr := ""
						nodeIDForQuery := ""
						if nodes, ok := s["nodes"].([]interface{}); ok && len(nodes) > 0 {
							nodeList := make([]string, len(nodes))
							for i, n := range nodes {
								nodeList[i] = fmt.Sprintf("%v", n)
							}
							nodeStr = nodeList[0]
							nodeIDForQuery = nodeList[0]
							if len(nodeList) > 1 {
								nodeStr = fmt.Sprintf("%s (+%d)", nodeStr, len(nodeList)-1)
							}
						}

						// Build CHUNK QNAME: <nodeid><distributionID>.<controlzone>
						queryStr := ""
						if nodeIDForQuery != "" && distID != "" {
							// Ensure node ID is FQDN (with trailing dot)
							nodeIDFQDN := nodeIDForQuery
							if !strings.HasSuffix(nodeIDFQDN, ".") {
								nodeIDFQDN = nodeIDFQDN + "."
							}
							// Ensure control zone has trailing dot
							controlZoneFQDN := controlZone
							if !strings.HasSuffix(controlZoneFQDN, ".") {
								controlZoneFQDN = controlZoneFQDN + "."
							}
							// QNAME format: <nodeid><distributionID>.<controlzone>
							// Remove trailing dot from control zone for concatenation, then add it back
							controlZoneClean := strings.TrimSuffix(controlZoneFQDN, ".")
							queryStr = fmt.Sprintf("%s%s.%s. CHUNK", nodeIDFQDN, distID, controlZoneClean)
						}

						// Get state and time
						state := "ongoing"
						timeStr := ""
						if completedAt, ok := s["completed_at"].(string); ok && completedAt != "" {
							state = "completed"
							if t, err := time.Parse(time.RFC3339, completedAt); err == nil {
								timeStr = t.Format("2006-01-02 15:04:05")
							} else {
								timeStr = completedAt
							}
						} else {
							// Use creation time for ongoing distributions
							if createdAt, ok := s["created_at"].(string); ok && createdAt != "" {
								if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
									timeStr = t.Format("2006-01-02 15:04:05")
								} else {
									timeStr = createdAt
								}
							}
						}

						// Build contents string
						zskCount := 0
						if z, ok := s["zsk_count"].(float64); ok {
							zskCount = int(z)
						}
						kskCount := 0
						if k, ok := s["ksk_count"].(float64); ok {
							kskCount = int(k)
						}

						keyTypeStr := ""
						if zskCount > 0 && kskCount > 0 {
							keyTypeStr = fmt.Sprintf("%d ZSK and %d KSK", zskCount, kskCount)
						} else if zskCount > 0 {
							keyTypeStr = fmt.Sprintf("%d ZSK", zskCount)
						} else if kskCount > 0 {
							keyTypeStr = fmt.Sprintf("%d KSK", kskCount)
						}

						zoneStr := ""
						zoneCount := 0
						contentType := ""
						if ct, ok := s["content_type"].(string); ok {
							contentType = ct
						}

						if zones, ok := s["zones"].([]interface{}); ok {
							zoneList := make([]string, len(zones))
							for i, z := range zones {
								zoneList[i] = fmt.Sprintf("%v", z)
							}
							zoneCount = len(zoneList)
							if zoneCount > 0 {
								zoneStr = strings.Join(zoneList, ", ")
								if zoneCount > 3 {
									zoneStr = strings.Join(zoneList[:3], ", ") + fmt.Sprintf(" (+%d more)", zoneCount-3)
								}
							}
						}

						contents := ""
						if contentType == "node_operations" {
							// For node_operations distributions, show components for the node
							contents = "updated list of node components"
						} else if contentType == "mgmt_operations" {
							// For management operations
							contents = "management operations"
						} else if zoneCount > 0 {
							contents = fmt.Sprintf("%s keys for %d zone(s), including %s", keyTypeStr, zoneCount, zoneStr)
						} else {
							contents = keyTypeStr + " keys"
						}

						rows = append(rows, fmt.Sprintf("%s | %s | %s | %s | %s | %s", distID, state, timeStr, nodeStr, contents, queryStr))
					}
				}

				if len(rows) > 1 {
					output := columnize.SimpleFormat(rows)
					fmt.Println(output)
				}
			}
		} else if dists, ok := resp["distributions"].([]interface{}); ok {
			// Fallback to old format
			if len(dists) == 0 {
				fmt.Println("No distributions found")
			} else {
				fmt.Println("\nDistribution IDs:")
				for _, dist := range dists {
					fmt.Printf("  %s\n", dist)
				}
			}
		}
	},
}

var kdcDistribPurgeCmd = &cobra.Command{
	Use:   "purge [--force]",
	Short: "Delete distributions",
	Long:  "Delete distributions from the database. By default, only completed distributions are deleted. Use --force to delete ALL distributions regardless of status.",
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		reqBody := map[string]interface{}{
			"command": "purge",
			"force":   force,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", reqBody)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if msg, ok := resp["msg"].(string); ok {
			fmt.Println(msg)
		} else if errorMsg, ok := resp["error_msg"].(string); ok {
			fmt.Printf("Error: %s\n", errorMsg)
			os.Exit(1)
		}
	},
}

var kdcDistribStateCmd = &cobra.Command{
	Use:   "state --distid <distribution-id>",
	Short: "Show detailed state of a distribution",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "distid")
		distID := cmd.Flag("distid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":         "state",
			"distribution_id": distID,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n\n", resp["msg"])

		if stateRaw, ok := resp["state"]; ok {
			if state, ok := stateRaw.(map[string]interface{}); ok {
				fmt.Printf("Distribution ID: %s\n", getString(state, "distribution_id", "DistributionID"))
				fmt.Printf("Zone: %s\n", getString(state, "zone_name", "ZoneName"))
				fmt.Printf("Key ID: %s\n", getString(state, "key_id", "KeyID"))
				fmt.Printf("Key State: %s\n", getString(state, "key_state", "KeyState"))
				fmt.Printf("Created At: %s\n", getString(state, "created_at", "CreatedAt"))
				fmt.Printf("All Confirmed: %v\n\n", getBool(state, "all_confirmed", "AllConfirmed"))

				if confirmedNodes, ok := state["confirmed_nodes"].([]interface{}); ok {
					fmt.Printf("Confirmed Nodes (%d):\n", len(confirmedNodes))
					for _, node := range confirmedNodes {
						fmt.Printf("  - %s\n", node)
					}
				}

				if pendingNodes, ok := state["pending_nodes"].([]interface{}); ok {
					fmt.Printf("\nPending Nodes (%d):\n", len(pendingNodes))
					if len(pendingNodes) == 0 {
						fmt.Println("  (none - all confirmed)")
					} else {
						for _, node := range pendingNodes {
							fmt.Printf("  - %s\n", node)
						}
					}
				}
			}
		}
	},
}

var kdcDistribCompletedCmd = &cobra.Command{
	Use:   "completed --distid <distribution-id>",
	Short: "Force mark a distribution as completed (even if nodes haven't confirmed)",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "distid")
		distID := cmd.Flag("distid").Value.String()

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":         "completed",
			"distribution_id": distID,
		}

		resp, err := sendKdcRequest(api, "/kdc/distrib", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDistribSingleCmd = &cobra.Command{
	Use:   "single --zone <zone-id> --keyid <key-id>",
	Short: "Trigger distribution of a specific standby ZSK to all nodes",
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "zonename")
		zoneName := cmd.Flag("zone").Value.String()
		keyid := cmd.Flag("keyid").Value.String()
		if keyid == "" {
			log.Fatalf("Error: --keyid is required")
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command":   "distrib-single",
			"zone_name": zoneName,
			"key_id":    keyid,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDistribMultiCmd = &cobra.Command{
	Use:   "multi [zone1] [zone2] ...",
	Short: "Distribute standby ZSK keys for one or more zones (auto-selects standby keys)",
	Long:  `Distributes standby ZSK keys for the specified zones. For each zone, automatically selects a standby ZSK and distributes it to all active nodes.`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Normalize zone names to FQDNs
		zones := make([]string, len(args))
		for i, zone := range args {
			zones[i] = dns.Fqdn(zone)
		}

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "distrib-multi",
			"zones":   zones,
		}

		// Add crypto flag if specified
		cryptoBackend, _ := cmd.Flags().GetString("crypto")
		if cryptoBackend != "" {
			cryptoBackend, err = validateCryptoBackend(cryptoBackend)
			if err != nil {
				log.Fatalf("Error: %v", err)
			}
			req["crypto"] = cryptoBackend
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		// Always show the summary message
		if msg, ok := resp["msg"].(string); ok && msg != "" {
			fmt.Printf("%s\n", msg)
		}

		// Always display detailed results, even if there are errors
		if resultsRaw, ok := resp["results"]; ok {
			if results, ok := resultsRaw.([]interface{}); ok {
				if len(results) > 0 {
					fmt.Printf("\nDetailed results:\n")
					for _, result := range results {
						if resultMap, ok := result.(map[string]interface{}); ok {
							zoneID := getString(resultMap, "zone_name", "ZoneName")
							status := getString(resultMap, "status", "Status")
							msg := getString(resultMap, "msg", "Msg")
							if status == "success" {
								fmt.Printf("  ✓ %s: %s\n", zoneID, msg)
							} else {
								fmt.Printf("  ✗ %s: %s\n", zoneID, msg)
							}
						}
					}
				}
			}
		}

		// If there was an error and no successful distributions, exit with error
		if resp["error"] == true {
			if resultsRaw, ok := resp["results"]; ok {
				if results, ok := resultsRaw.([]interface{}); ok {
					hasSuccess := false
					for _, result := range results {
						if resultMap, ok := result.(map[string]interface{}); ok {
							if status := getString(resultMap, "status", "Status"); status == "success" {
								hasSuccess = true
								break
							}
						}
					}
					if !hasSuccess {
						if errorMsg, ok := resp["error_msg"].(string); ok {
							log.Fatalf("Error: %s", errorMsg)
						} else {
							log.Fatalf("Error: Failed to distribute keys for all zones")
						}
					}
				}
			} else {
				if errorMsg, ok := resp["error_msg"].(string); ok {
					log.Fatalf("Error: %s", errorMsg)
				} else {
					log.Fatalf("Error: Distribution failed")
				}
			}
		}
	},
}

func init() {
	KdcDistribCmd.AddCommand(kdcDistribListCmd, kdcDistribStateCmd, kdcDistribCompletedCmd, kdcDistribSingleCmd, kdcDistribMultiCmd, kdcDistribPurgeCmd)

	kdcDistribSingleCmd.Flags().StringP("keyid", "k", "", "Key ID (must be a ZSK in standby state)")
	kdcDistribSingleCmd.MarkFlagRequired("keyid")

	kdcDistribStateCmd.Flags().String("distid", "", "Distribution ID")
	kdcDistribStateCmd.MarkFlagRequired("distid")

	kdcDistribCompletedCmd.Flags().String("distid", "", "Distribution ID")
	kdcDistribCompletedCmd.MarkFlagRequired("distid")

	kdcDistribPurgeCmd.Flags().Bool("force", false, "Delete ALL distributions (not just completed ones)")

	kdcDistribMultiCmd.Flags().String("crypto", "", "Force crypto backend (jose). If not specified, uses any backend the node supports.")
}
