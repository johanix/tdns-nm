/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC debug CLI commands
 */
package cli

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var KdcDebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug utilities for KDC",
}

var KdcDebugDistribCmd = &cobra.Command{
	Use:   "distrib",
	Short: "Manage test distributions",
	Long:  `Commands for creating, listing, and deleting test distributions.`,
}

var kdcDebugDistribGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Create a test distribution with clear_text or encrypted_text content",
	Long:  `Creates a persistent test distribution that can be queried by KRS. The distribution will contain text read from a file (or default lorem ipsum if no file specified) that will be chunked and distributed. Use --content-type to choose 'clear_text' (default) or 'encrypted_text' (JOSE encrypted and signed).`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "nodeid", "distid")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		distributionID := cmd.Flag("distid").Value.String()
		nodeIDFQDN := cmd.Flag("nodeid").Value.String()
		testTextFile := cmd.Flag("file").Value.String()

		var testText string
		if testTextFile != "" {
			// Read from file
			data, err := os.ReadFile(testTextFile)
			if err != nil {
				log.Fatalf("Error reading file %s: %v", testTextFile, err)
			}
			testText = string(data)
		}

		contentType := cmd.Flag("content-type").Value.String()
		if contentType == "" {
			contentType = "clear_text" // Default
		}
		if contentType != "clear_text" && contentType != "encrypted_text" {
			log.Fatalf("Error: --content-type must be 'clear_text' or 'encrypted_text' (got: %s)", contentType)
		}

		req := map[string]interface{}{
			"command":         "test-distribution",
			"distribution_id": distributionID,
			"node_id":         nodeIDFQDN,
			"content_type":    contentType,
		}
		if testText != "" {
			req["test_text"] = testText
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("Test distribution created successfully\n")
		fmt.Printf("  Distribution ID: %s\n", resp["distribution_id"])
		fmt.Printf("  Node ID: %s\n", nodeIDFQDN)
		if chunkCount, ok := resp["chunk_count"].(float64); ok {
			fmt.Printf("  Chunk count: %.0f\n", chunkCount)
		}
		fmt.Printf("  Message: %s\n", resp["msg"])
	},
}

var kdcDebugDistribListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all distribution IDs",
	Long:  `Lists all distribution IDs (both test and real) currently stored in the KDC.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "list-distributions",
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])

		// Try to get distribution_infos first (new format with node info)
		if distInfosRaw, ok := resp["distribution_infos"].([]interface{}); ok {
			if len(distInfosRaw) > 0 {
				fmt.Printf("\nDistribution IDs:\n")
				for _, distInfoRaw := range distInfosRaw {
					if distInfo, ok := distInfoRaw.(map[string]interface{}); ok {
						distID, _ := distInfo["distribution_id"].(string)
						nodesRaw, _ := distInfo["nodes"].([]interface{})
						nodes := make([]string, 0, len(nodesRaw))
						for _, nodeRaw := range nodesRaw {
							if node, ok := nodeRaw.(string); ok {
								nodes = append(nodes, node)
							}
						}
						if len(nodes) > 0 {
							fmt.Printf("  - %s (applies to nodes %s)\n", distID, strings.Join(nodes, ", "))
						} else {
							fmt.Printf("  - %s\n", distID)
						}
					}
				}
			}
		} else if distributions, ok := resp["distributions"].([]interface{}); ok {
			// Fallback to old format (backward compatibility)
			if len(distributions) > 0 {
				fmt.Printf("\nDistribution IDs:\n")
				for _, distID := range distributions {
					if id, ok := distID.(string); ok {
						fmt.Printf("  - %s\n", id)
					}
				}
			}
		}
	},
}

var kdcDebugDistribDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a distribution by ID",
	Long:  `Deletes a distribution (both from database and cache) by its distribution ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs(cmd, "distid")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		distributionID := cmd.Flag("distid").Value.String()

		req := map[string]interface{}{
			"command":         "delete-distribution",
			"distribution_id": distributionID,
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
	},
}

var kdcDebugSetChunkSizeCmd = &cobra.Command{
	Use:   "set-chunk-size",
	Short: "Set the maximum chunk size for new distributions",
	Long:  `Sets the maximum chunk size (in bytes) for CHUNK records. This only affects new distributions created after this change. Existing distributions are not affected.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		chunkSizeStr := cmd.Flag("size").Value.String()
		if chunkSizeStr == "" {
			log.Fatalf("Error: --size is required")
		}

		var chunkSize int
		if _, err := fmt.Sscanf(chunkSizeStr, "%d", &chunkSize); err != nil {
			log.Fatalf("Error: invalid chunk size: %v", err)
		}

		if chunkSize <= 0 {
			log.Fatalf("Error: chunk size must be greater than 0")
		}

		req := map[string]interface{}{
			"command":    "set-chunk-size",
			"chunk_size": chunkSize,
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		if size, ok := resp["chunk_size"].(float64); ok {
			fmt.Printf("  Current chunk size: %.0f bytes\n", size)
		}
	},
}

var kdcDebugGetChunkSizeCmd = &cobra.Command{
	Use:   "get-chunk-size",
	Short: "Get the current maximum chunk size",
	Long:  `Gets the current maximum chunk size (in bytes) for CHUNK records.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := map[string]interface{}{
			"command": "get-chunk-size",
		}

		resp, err := sendKdcRequest(api, "/kdc/debug", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		fmt.Printf("%s\n", resp["msg"])
		if size, ok := resp["chunk_size"].(float64); ok {
			fmt.Printf("  Current chunk size: %.0f bytes\n", size)
		}
	},
}

func init() {
	KdcDebugDistribCmd.AddCommand(kdcDebugDistribGenerateCmd, kdcDebugDistribListCmd, kdcDebugDistribDeleteCmd)
	KdcDebugCmd.AddCommand(KdcDebugDistribCmd, kdcDebugSetChunkSizeCmd, kdcDebugGetChunkSizeCmd)

	kdcDebugDistribGenerateCmd.Flags().String("distid", "", "Distribution ID (hex, e.g., a1b2)")
	kdcDebugDistribGenerateCmd.Flags().StringP("nodeid", "n", "", "Node ID")
	kdcDebugDistribGenerateCmd.Flags().StringP("file", "f", "", "File containing text (if not provided, uses default lorem ipsum)")
	kdcDebugDistribGenerateCmd.Flags().StringP("content-type", "t", "clear_text", "Content type: 'clear_text' or 'encrypted_text' (default: clear_text)")
	kdcDebugDistribGenerateCmd.MarkFlagRequired("distid")
	kdcDebugDistribGenerateCmd.MarkFlagRequired("nodeid")

	kdcDebugDistribDeleteCmd.Flags().String("distid", "", "Distribution ID to delete")
	kdcDebugDistribDeleteCmd.MarkFlagRequired("distid")

	kdcDebugSetChunkSizeCmd.Flags().StringP("size", "s", "", "Chunk size in bytes")
	kdcDebugSetChunkSizeCmd.MarkFlagRequired("size")
}
