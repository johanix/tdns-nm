/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC debug CLI commands
 */
package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/hpke"
	"github.com/johanix/tdns/v2"
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
	Long:  `Creates a persistent test distribution that can be queried by KRS. The distribution will contain text read from a file (or default lorem ipsum if no file specified) that will be chunked and distributed. Use --content-type to choose 'clear_text' (default) or 'encrypted_text' (HPKE encrypted).`,
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

var kdcDebugHpkeEncryptCmd = &cobra.Command{
	Use:   "hpke-encrypt --zone <zone-id> --keyid <key-id> --nodeid <node-id> [--output <file>]",
	Short: "Test HPKE encryption of a DNSSEC key for a node",
	Long:  `Encrypts a DNSSEC key's private key material using HPKE with a node's long-term public key. This is a test/debug command.`,
	Run: func(cmd *cobra.Command, args []string) {
		PrepArgs("zonename")

		api, err := getApiClient(true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		keyID := cmd.Flag("keyid").Value.String()
		nodeID := cmd.Flag("nodeid").Value.String()
		outputFile := cmd.Flag("output").Value.String()

		if keyID == "" {
			log.Fatalf("Error: --keyid is required")
		}
		if nodeID == "" {
			log.Fatalf("Error: --nodeid is required")
		}

		// Request encryption via API
		req := map[string]interface{}{
			"command":   "encrypt-key",
			"zone_name": tdns.Globals.Zonename,
			"key_id":    keyID,
			"node_id":   nodeID,
		}

		resp, err := sendKdcRequest(api, "/kdc/zone", req)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if resp["error"] == true {
			log.Fatalf("Error: %v", resp["error_msg"])
		}

		// Extract encrypted data
		encryptedKeyRaw, ok := resp["encrypted_key"]
		if !ok {
			log.Fatalf("Error: 'encrypted_key' not found in response")
		}

		ephemeralPubKeyRaw, ok := resp["ephemeral_pub_key"]
		if !ok {
			log.Fatalf("Error: 'ephemeral_pub_key' not found in response")
		}

		distributionID := getString(resp, "distribution_id", "DistributionID")

		// Convert to []byte (assuming base64 encoding from JSON)
		var encryptedKey, ephemeralPubKey []byte
		if encStr, ok := encryptedKeyRaw.(string); ok {
			encryptedKey, err = base64.StdEncoding.DecodeString(encStr)
			if err != nil {
				log.Fatalf("Error decoding encrypted_key: %v", err)
			}
		} else if encBytes, ok := encryptedKeyRaw.([]byte); ok {
			encryptedKey = encBytes
		} else {
			log.Fatalf("Error: encrypted_key has unexpected type: %T", encryptedKeyRaw)
		}

		if ephemStr, ok := ephemeralPubKeyRaw.(string); ok {
			ephemeralPubKey, err = base64.StdEncoding.DecodeString(ephemStr)
			if err != nil {
				log.Fatalf("Error decoding ephemeral_pub_key: %v", err)
			}
		} else if ephemBytes, ok := ephemeralPubKeyRaw.([]byte); ok {
			ephemeralPubKey = ephemBytes
		} else {
			log.Fatalf("Error: ephemeral_pub_key has unexpected type: %T", ephemeralPubKeyRaw)
		}

		// Output results
		fmt.Printf("Encryption successful!\n")
		fmt.Printf("Distribution ID: %s\n", distributionID)
		fmt.Printf("Encrypted key size: %d bytes\n", len(encryptedKey))
		fmt.Printf("Ephemeral public key size: %d bytes\n", len(ephemeralPubKey))
		fmt.Printf("Ephemeral public key (hex): %x\n", ephemeralPubKey)

		if outputFile != "" {
			// Write encrypted key to file
			output := "# HPKE-encrypted DNSSEC key\n"
			output += fmt.Sprintf("# Distribution ID: %s\n", distributionID)
			output += fmt.Sprintf("# Zone: %s\n", tdns.Globals.Zonename)
			output += fmt.Sprintf("# Key ID: %s\n", keyID)
			output += fmt.Sprintf("# Node ID: %s\n", nodeID)
			output += fmt.Sprintf("# Encrypted at: %s\n", time.Now().Format(time.RFC3339))
			output += fmt.Sprintf("# Ephemeral public key (hex): %x\n", ephemeralPubKey)
			output += "# Encrypted key (base64):\n"
			output += base64.StdEncoding.EncodeToString(encryptedKey) + "\n"

			if err := os.WriteFile(outputFile, []byte(output), 0600); err != nil {
				log.Fatalf("Error writing output file: %v", err)
			}
			fmt.Printf("\nEncrypted key written to: %s\n", outputFile)
		}
	},
}

var kdcDebugHpkeGenerateCmd = &cobra.Command{
	Use:   "hpke-generate [prefix]",
	Short: "Generate an HPKE keypair for testing",
	Long:  `Generates an HPKE keypair and writes the public key to {prefix}.publickey and private key to {prefix}.privatekey (both hex encoded).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prefix := args[0]
		pubKeyFile := prefix + ".publickey"
		privKeyFile := prefix + ".privatekey"

		// Generate HPKE keypair
		pubKey, privKey, err := hpke.GenerateKeyPair()
		if err != nil {
			log.Fatalf("Error generating HPKE keypair: %v", err)
		}

		// Format keys as hex
		pubKeyHex := fmt.Sprintf("%x", pubKey)
		privKeyHex := fmt.Sprintf("%x", privKey)

		// Create public key file with comments
		pubKeyContent := fmt.Sprintf(`# HPKE Public Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# This is the public key for HPKE (Hybrid Public Key Encryption).
# It can be safely shared and used to encrypt data for the holder of the corresponding private key.
#
%s
`, time.Now().Format(time.RFC3339), pubKeyHex)

		// Create private key file with comments
		privKeyContent := fmt.Sprintf(`# HPKE Private Key (X25519)
# Generated: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
# 
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
#
%s
`, time.Now().Format(time.RFC3339), privKeyHex)

		// Write public key file (readable by owner and group, not others)
		if err := os.WriteFile(pubKeyFile, []byte(pubKeyContent), 0644); err != nil {
			log.Fatalf("Error writing public key to file: %v", err)
		}

		// Write private key file (readable only by owner)
		if err := os.WriteFile(privKeyFile, []byte(privKeyContent), 0600); err != nil {
			log.Fatalf("Error writing private key to file: %v", err)
		}

		fmt.Printf("HPKE keypair generated successfully:\n")
		fmt.Printf("  Public key:  %s\n", pubKeyFile)
		fmt.Printf("  Private key: %s\n", privKeyFile)
		fmt.Printf("\nTo add this as a node, use:\n")
		fmt.Printf("  tdns-cli kdc node add --nodeid <node-id> --nodename <node-name> --pubkeyfile %s\n", pubKeyFile)
	},
}

var kdcDebugHpkeDecryptCmd = &cobra.Command{
	Use:   "hpke-decrypt --encrypted-file <file> --private-key-file <file>",
	Short: "Test HPKE decryption of an encrypted DNSSEC key",
	Long:  `Decrypts an HPKE-encrypted DNSSEC key file using a node's private key. This is a test/debug command.`,
	Run: func(cmd *cobra.Command, args []string) {
		encryptedFile := cmd.Flag("encrypted-file").Value.String()
		privateKeyFile := cmd.Flag("private-key-file").Value.String()

		if encryptedFile == "" {
			log.Fatalf("Error: --encrypted-file is required")
		}
		if privateKeyFile == "" {
			log.Fatalf("Error: --private-key-file is required")
		}

		// Read encrypted key file
		encryptedData, err := os.ReadFile(encryptedFile)
		if err != nil {
			log.Fatalf("Error reading encrypted file: %v", err)
		}

		// Parse the encrypted file (it has comments and base64 data)
		lines := strings.Split(string(encryptedData), "\n")
		var encryptedKeyBase64 string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "Encrypted key (base64):") {
				// The base64 data should be on the next line
				continue
			} else if len(line) > 50 {
				// Likely the base64 encrypted key
				encryptedKeyBase64 = line
			}
		}

		if encryptedKeyBase64 == "" {
			log.Fatalf("Error: could not find encrypted key in file")
		}

		// Decode base64 encrypted key
		encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyBase64)
		if err != nil {
			log.Fatalf("Error decoding base64 encrypted key: %v", err)
		}

		// Read private key file
		privateKeyData, err := os.ReadFile(privateKeyFile)
		if err != nil {
			log.Fatalf("Error reading private key file: %v", err)
		}

		// Parse private key (skip comments, decode hex)
		privKeyLines := strings.Split(string(privateKeyData), "\n")
		var privKeyHex string
		for _, line := range privKeyLines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				privKeyHex += line
			}
		}

		if privKeyHex == "" {
			log.Fatalf("Error: could not find private key in file")
		}

		// Decode hex private key
		privateKey, err := hex.DecodeString(privKeyHex)
		if err != nil {
			log.Fatalf("Error decoding hex private key: %v", err)
		}

		if len(privateKey) != 32 {
			log.Fatalf("Error: private key must be 32 bytes (got %d)", len(privateKey))
		}

		// Decrypt using HPKE
		// Note: HPKE Base mode extracts ephemeral key from ciphertext, so we don't need ephemeralPubKeyHex
		plaintext, err := hpke.Decrypt(privateKey, nil, encryptedKey)
		if err != nil {
			log.Fatalf("Error decrypting: %v", err)
		}

		fmt.Printf("Decryption successful!\n")
		fmt.Printf("Decrypted key size: %d bytes\n", len(plaintext))
		fmt.Printf("\nDecrypted private key (PEM format):\n")
		fmt.Printf("%s\n", string(plaintext))
	},
}

func init() {
	KdcDebugDistribCmd.AddCommand(kdcDebugDistribGenerateCmd, kdcDebugDistribListCmd, kdcDebugDistribDeleteCmd)
	KdcDebugCmd.AddCommand(kdcDebugHpkeGenerateCmd, kdcDebugHpkeEncryptCmd, kdcDebugHpkeDecryptCmd,
		KdcDebugDistribCmd, kdcDebugSetChunkSizeCmd, kdcDebugGetChunkSizeCmd)

	kdcDebugHpkeEncryptCmd.Flags().StringP("keyid", "k", "", "DNSSEC key ID to encrypt")
	kdcDebugHpkeEncryptCmd.Flags().StringP("nodeid", "n", "", "Node ID to encrypt for")
	kdcDebugHpkeEncryptCmd.Flags().StringP("output", "o", "", "Output file for encrypted key (optional)")
	kdcDebugHpkeEncryptCmd.MarkFlagRequired("keyid")
	kdcDebugHpkeEncryptCmd.MarkFlagRequired("nodeid")

	kdcDebugHpkeDecryptCmd.Flags().StringP("encrypted-file", "e", "", "File containing encrypted key")
	kdcDebugHpkeDecryptCmd.Flags().StringP("private-key-file", "p", "", "File containing node's HPKE private key (hex)")
	kdcDebugHpkeDecryptCmd.MarkFlagRequired("encrypted-file")
	kdcDebugHpkeDecryptCmd.MarkFlagRequired("private-key-file")

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
