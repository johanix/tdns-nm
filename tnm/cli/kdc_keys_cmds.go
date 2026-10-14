/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC key management CLI commands (JOSE)
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"

	"github.com/johanix/tdns-nm/tnm/kdc"
)

var KdcKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage the KDC long-term JOSE keypair",
	Long: `Commands for managing the KDC's long-term JOSE (P-256) keypair.
The keypair is used for:
  - Encrypting enrollment confirmations sent to KRS nodes
  - Decrypting enrollment requests from KRS nodes
  - Signing distributions (JWS) and encrypting them to nodes (JWE)

The keypair must be configured in the KDC config file as kdc_jose_priv_key.
Enrollment packages include its public key.`,
}

var kdcKeysListCmd = &cobra.Command{
	Use:   "list [--jose-file <path>]",
	Short: "List the KDC long-term keypair",
	Long: `List the KDC long-term JOSE keypair with its key ID, algorithm, creation timestamp, and file path.

Key IDs are derived from the public key using SHA-256 (first 8 hex characters) for easy reference:
  - Format: {algorithm}_{hash8}
  - Example: jose_e5f6a7b8

Specify the key file path directly:
  kdc-cli keys list --jose-file /etc/tdns/kdc/kdc.jose.privatekey`,
	Run: func(cmd *cobra.Command, args []string) {
		joseFile, _ := cmd.Flags().GetString("jose-file")

		var rows []string
		rows = append(rows, "KeyID | Algorithm | Size | Created | File")

		// Try to load JOSE key
		if joseFile != "" {
			pubKey, err := kdc.GetKdcJosePubKey(joseFile)
			if err == nil {
				keyID := kdc.GenerateKeyID("jose", pubKey)
				fileInfo, statErr := os.Stat(joseFile)
				var createdTime, absPath string
				if statErr != nil {
					createdTime = "unknown"
					absPath = fmt.Sprintf("%s (stat error: %v)", joseFile, statErr)
				} else {
					createdTime = fileInfo.ModTime().Format("2006-01-02 15:04:05")
					absPathVal, absErr := filepath.Abs(joseFile)
					if absErr != nil {
						absPath = fmt.Sprintf("%s (abs error: %v)", joseFile, absErr)
					} else {
						absPath = absPathVal
					}
				}
				rows = append(rows, fmt.Sprintf("%s | JOSE | 256b | %s | %s", keyID, createdTime, absPath))
			} else {
				rows = append(rows, fmt.Sprintf("(error) | JOSE | --- | --- | %s (error: %v)", joseFile, err))
			}
		} else {
			rows = append(rows, "(not configured) | JOSE | --- | --- | (use --jose-file to specify path)")
		}

		fmt.Println(columnize.SimpleFormat(rows))
	},
}

var kdcKeysGenerateCmd = &cobra.Command{
	Use:   "generate [--jose-outfile <path>]",
	Short: "Generate the KDC JOSE keypair",
	Long: `Generate the KDC long-term JOSE keypair (P-256).

  --jose-outfile      Path for JOSE private key file (default: ./kdc.jose.privatekey)

Example:
  kdc-cli keys generate --jose-outfile /etc/tdns/kdc/kdc.jose.privatekey

The single P-256 key is used for both encryption and signing.

WARNING: If you generate a NEW keypair, you must regenerate all enrollment blobs
that were created with the old public key, as they will no longer be decryptable.`,
	Run: func(cmd *cobra.Command, args []string) {
		joseOutfile, _ := cmd.Flags().GetString("jose-outfile")
		if joseOutfile == "" {
			joseOutfile = "./kdc.jose.privatekey"
		}

		// Generate JOSE key
		{
			if _, err := os.Stat(joseOutfile); err == nil {
				log.Fatalf("Error: JOSE key file already exists: %s\nUse a different path or remove the existing file first.", joseOutfile)
			}

			// Generate JOSE keypair
			backend, err := crypto.GetBackend("jose")
			if err != nil {
				log.Fatalf("Error getting JOSE backend: %v", err)
			}

			privKey, pubKey, err := backend.GenerateKeypair()
			if err != nil {
				log.Fatalf("Error generating JOSE keypair: %v", err)
			}

			// Serialize keys
			privKeyBytes, err := backend.SerializePrivateKey(privKey)
			if err != nil {
				log.Fatalf("Error serializing JOSE private key: %v", err)
			}
			pubKeyBytes, err := backend.SerializePublicKey(pubKey)
			if err != nil {
				log.Fatalf("Error serializing JOSE public key: %v", err)
			}

			// Parse JSON to pretty-print it
			var prettyJSON interface{}
			err = json.Unmarshal(privKeyBytes, &prettyJSON)
			if err != nil {
				log.Fatalf("Error parsing JOSE private key JSON: %v", err)
			}

			prettyJSONBytes, err := json.MarshalIndent(prettyJSON, "", "  ")
			if err != nil {
				log.Fatalf("Error formatting JOSE private key JSON: %v", err)
			}

			generatedAt := time.Now().Format(time.RFC3339)
			keyID := kdc.GenerateKeyID("jose", pubKeyBytes)

			keyContent := fmt.Sprintf(`# KDC JOSE Private Key (P-256)
# Generated: %s
# KeyID: %s
# Algorithm: P-256 (ECDSA for JWE with ECDH-ES)
# Key Size: 256 bits (P-256 curve)
# Format: JWK (JSON Web Key)
#
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
# This key is used by KDC to decrypt enrollment requests and encrypt enrollment confirmations.
#
# To use this keypair:
# 1. Add the following to your KDC config file (under 'kdc:' section):
#    kdc_jose_priv_key: %s
# 2. Restart the KDC
#
# WARNING: If you generate a NEW keypair, you must regenerate all enrollment blobs
# that were created with the old public key, as they will no longer be decryptable.
#
%s
`, generatedAt, keyID, joseOutfile, prettyJSONBytes)

			// Write key file with secure permissions
			if err := os.WriteFile(joseOutfile, []byte(keyContent), 0600); err != nil {
				log.Fatalf("Error writing JOSE key file: %v", err)
			}

			// Get absolute path for display
			absPath, err := filepath.Abs(joseOutfile)
			if err != nil {
				absPath = joseOutfile
			}

			fmt.Printf("✓ JOSE keypair generated successfully!\n")
			fmt.Printf("  KeyID:     %s\n", keyID)
			fmt.Printf("  File:      %s\n\n", absPath)
		}

		// Print next steps
		fmt.Printf("Next steps:\n")

		// Build list of steps conditionally
		steps := []string{}

		// Always include review step
		steps = append(steps, "Review the generated key files")

		// Add JOSE config step
		absPath, _ := filepath.Abs(joseOutfile)
		steps = append(steps, fmt.Sprintf("Add to your KDC config: kdc_jose_priv_key: %s", absPath))

		// Always include restart and enrollment blob steps
		steps = append(steps, "Restart the KDC")

		steps = append(steps, "Generate enrollment blobs (which will include the generated public key)")

		// Print steps with sequential numbering
		for i, step := range steps {
			fmt.Printf("  %d. %s\n", i+1, step)
		}

	},
}

func init() {
	KdcKeysCmd.AddCommand(kdcKeysListCmd, kdcKeysGenerateCmd)

	// Keys list command flags
	kdcKeysListCmd.Flags().String("jose-file", "", "Path to JOSE private key file")

	// Keys generate command flags
	kdcKeysGenerateCmd.Flags().String("jose-outfile", "", "Output file path for JOSE private key (default: ./kdc.jose.privatekey)")
}
