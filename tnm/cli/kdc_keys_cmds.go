/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC key management CLI commands (HPKE and JOSE)
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	hpkebackend "github.com/johanix/tdns-nm/tnm/crypto/hpke"
	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/johanix/tdns-transport/v2/hpke"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"

	"github.com/johanix/tdns-nm/tnm/kdc"
)

var KdcKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage KDC long-term keypairs (HPKE and JOSE)",
	Long: `Commands for managing the KDC's long-term keypairs.
The KDC must have both HPKE (X25519) and JOSE (P-256) keypairs.
These keypairs are used for:
  - Encrypting enrollment confirmations sent to KRS nodes
  - Decrypting enrollment requests from KRS nodes
  - Distributing keys to nodes with different crypto backends

Both keypairs must be configured in the KDC config file as:
  - kdc_hpke_priv_key
  - kdc_jose_priv_key

Enrollment packages include both public keys to allow nodes to choose their preferred backend.`,
}

var kdcKeysListCmd = &cobra.Command{
	Use:   "list [--hpke-file <path>] [--jose-file <path>]",
	Short: "List all KDC long-term keypairs",
	Long: `List all configured KDC long-term keypairs with their key IDs, algorithms, creation timestamps, and file paths.

Key IDs are derived from the public keys using SHA-256 (first 8 hex characters) for easy reference:
  - Format: {algorithm}_{hash8}
  - Example: hpke_a1b2c3d4, jose_e5f6a7b8

You can optionally specify key file paths directly:
  kdc-cli keys list --hpke-file /etc/tdns/kdc/kdc.hpke.privatekey \
                    --jose-file /etc/tdns/kdc/kdc.jose.privatekey`,
	Run: func(cmd *cobra.Command, args []string) {
		hpkeFile, _ := cmd.Flags().GetString("hpke-file")
		joseFile, _ := cmd.Flags().GetString("jose-file")

		var rows []string
		rows = append(rows, "KeyID | Algorithm | Size | Created | File")

		// Try to load HPKE key
		if hpkeFile != "" {
			pubKey, err := kdc.GetKdcHpkePubKey(hpkeFile)
			if err == nil {
				keyID := kdc.GenerateKeyID("hpke", pubKey)
				fileInfo, statErr := os.Stat(hpkeFile)
				var createdTime, absPath string
				if statErr != nil {
					createdTime = "unknown"
					absPath = fmt.Sprintf("%s (stat error: %v)", hpkeFile, statErr)
				} else {
					createdTime = fileInfo.ModTime().Format("2006-01-02 15:04:05")
					absPathVal, absErr := filepath.Abs(hpkeFile)
					if absErr != nil {
						absPath = fmt.Sprintf("%s (abs error: %v)", hpkeFile, absErr)
					} else {
						absPath = absPathVal
					}
				}
				rows = append(rows, fmt.Sprintf("%s | HPKE | 256b | %s | %s", keyID, createdTime, absPath))
			} else {
				rows = append(rows, fmt.Sprintf("(error) | HPKE | --- | --- | %s (error: %v)", hpkeFile, err))
			}
		} else {
			rows = append(rows, "(not configured) | HPKE | --- | --- | (use --hpke-file to specify path)")
		}

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
	Use:   "generate [--hpke] [--hpke-outfile <path>] [--hpke-signing] [--hpke-signing-outfile <path>] [--jose] [--jose-outfile <path>]",
	Short: "Generate KDC keypairs (HPKE, HPKE signing, and/or JOSE)",
	Long: `Generate KDC long-term keypairs.

Must specify at least one of --hpke, --hpke-signing, or --jose flags.

HPKE encryption keypair (X25519):
  --hpke              Generate new HPKE encryption keypair
  --hpke-outfile      Path for HPKE private key file (default: ./kdc.hpke.privatekey)

HPKE signing keypair (P-256 ECDSA):
  --hpke-signing      Generate new HPKE signing keypair (for JWS signatures)
  --hpke-signing-outfile  Path for HPKE signing private key file (default: ./kdc.hpke.signing.privatekey)

JOSE keypair (P-256):
  --jose              Generate new JOSE keypair
  --jose-outfile      Path for JOSE private key file (default: ./kdc.jose.privatekey)

Examples:
  kdc-cli keys generate --hpke --hpke-outfile /etc/tdns/kdc/kdc.hpke.privatekey
  kdc-cli keys generate --hpke-signing --hpke-signing-outfile /etc/tdns/kdc/kdc.hpke.signing.privatekey
  kdc-cli keys generate --jose --jose-outfile /etc/tdns/kdc/kdc.jose.privatekey
  kdc-cli keys generate --hpke --hpke-outfile /etc/tdns/kdc/kdc.hpke.privatekey \
                        --hpke-signing --hpke-signing-outfile /etc/tdns/kdc/kdc.hpke.signing.privatekey \
                        --jose --jose-outfile /etc/tdns/kdc/kdc.jose.privatekey

Note: HPKE backends require TWO keys:
  - X25519 key for encryption (--hpke)
  - P-256 ECDSA key for signing (--hpke-signing)

JOSE backends can use a single P-256 key for both encryption and signing.

WARNING: If you generate NEW keypairs, you must regenerate all enrollment blobs
that were created with the old public keys, as they will no longer be decryptable.`,
	Run: func(cmd *cobra.Command, args []string) {
		genHpke, _ := cmd.Flags().GetBool("hpke")
		genHpkeSigning, _ := cmd.Flags().GetBool("hpke-signing")
		genJose, _ := cmd.Flags().GetBool("jose")
		hpkeOutfile, _ := cmd.Flags().GetString("hpke-outfile")
		hpkeSigningOutfile, _ := cmd.Flags().GetString("hpke-signing-outfile")
		joseOutfile, _ := cmd.Flags().GetString("jose-outfile")

		// Require at least one key type
		if !genHpke && !genHpkeSigning && !genJose {
			log.Fatalf("Error: Must specify at least one of --hpke, --hpke-signing, or --jose")
		}

		// Set defaults if not specified
		if genHpke && hpkeOutfile == "" {
			hpkeOutfile = "./kdc.hpke.privatekey"
		}
		if genHpkeSigning && hpkeSigningOutfile == "" {
			hpkeSigningOutfile = "./kdc.hpke.signing.privatekey"
		}
		if genJose && joseOutfile == "" {
			joseOutfile = "./kdc.jose.privatekey"
		}

		// Generate HPKE key if requested
		if genHpke {
			if _, err := os.Stat(hpkeOutfile); err == nil {
				log.Fatalf("Error: HPKE key file already exists: %s\nUse a different path or remove the existing file first.", hpkeOutfile)
			}

			// Generate HPKE keypair
			pubKey, privKey, err := hpke.GenerateKeyPair()
			if err != nil {
				log.Fatalf("Error generating HPKE keypair: %v", err)
			}

			// Format key file content
			pubKeyHex := fmt.Sprintf("%x", pubKey)
			privKeyHex := fmt.Sprintf("%x", privKey)
			generatedAt := time.Now().Format(time.RFC3339)
			keyID := kdc.GenerateKeyID("hpke", pubKey)

			keyContent := fmt.Sprintf(`# KDC HPKE Private Key (X25519)
# Generated: %s
# KeyID: %s
# Algorithm: X25519 (HPKE KEM)
# Key Size: 32 bytes (256 bits)
# Format: Hexadecimal
#
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can decrypt
# data encrypted with the corresponding public key.
# This key is used by KDC to decrypt enrollment requests and encrypt enrollment confirmations.
#
# Public Key: %s
#
# To use this keypair:
# 1. Add the following to your KDC config file (under 'kdc:' section):
#    kdc_hpke_priv_key: %s
# 2. Restart the KDC
#
# WARNING: If you generate a NEW keypair, you must regenerate all enrollment blobs
# that were created with the old public key, as they will no longer be decryptable.
#
%s
`, generatedAt, keyID, pubKeyHex, hpkeOutfile, privKeyHex)

			// Write key file with secure permissions
			if err := os.WriteFile(hpkeOutfile, []byte(keyContent), 0600); err != nil {
				log.Fatalf("Error writing HPKE key file: %v", err)
			}

			// Get absolute path for display
			absPath, err := filepath.Abs(hpkeOutfile)
			if err != nil {
				absPath = hpkeOutfile
			}

			fmt.Printf("✓ HPKE encryption keypair generated successfully!\n")
			fmt.Printf("  KeyID:     %s\n", keyID)
			fmt.Printf("  File:      %s\n", absPath)
			fmt.Printf("  Public key: %s\n\n", pubKeyHex)
		}

		// Generate HPKE signing key if requested
		if genHpkeSigning {
			if _, err := os.Stat(hpkeSigningOutfile); err == nil {
				log.Fatalf("Error: HPKE signing key file already exists: %s\nUse a different path or remove the existing file first.", hpkeSigningOutfile)
			}

			// Generate HPKE signing keypair (P-256 ECDSA)
			backend, err := crypto.GetBackend("hpke")
			if err != nil {
				log.Fatalf("Error getting HPKE backend: %v", err)
			}

			// Cast to HPKE backend to access signing key methods
			hpkeBackend, ok := backend.(*hpkebackend.Backend)
			if !ok {
				log.Fatalf("Error: backend is not HPKE backend")
			}

			// Generate P-256 ECDSA signing keypair
			privKey, pubKey, err := hpkeBackend.GenerateSigningKeypair()
			if err != nil {
				log.Fatalf("Error generating HPKE signing keypair: %v", err)
			}

			// Serialize keys
			privKeyBytes, err := hpkeBackend.SerializeSigningKey(privKey)
			if err != nil {
				log.Fatalf("Error serializing HPKE signing private key: %v", err)
			}
			pubKeyBytes, err := hpkeBackend.SerializeVerifyKey(pubKey)
			if err != nil {
				log.Fatalf("Error serializing HPKE signing public key: %v", err)
			}

			// Parse JSON to pretty-print it
			var prettyJSON interface{}
			err = json.Unmarshal(privKeyBytes, &prettyJSON)
			if err != nil {
				log.Fatalf("Error parsing HPKE signing private key JSON: %v", err)
			}

			prettyJSONBytes, err := json.MarshalIndent(prettyJSON, "", "  ")
			if err != nil {
				log.Fatalf("Error formatting HPKE signing private key JSON: %v", err)
			}

			generatedAt := time.Now().Format(time.RFC3339)
			keyID := kdc.GenerateKeyID("hpke_sign", pubKeyBytes)

			keyContent := fmt.Sprintf(`# KDC HPKE Signing Private Key (P-256 ECDSA)
# Generated: %s
# KeyID: %s
# Algorithm: P-256 ECDSA (for signing HPKE distributions)
# Key Size: 256 bits (P-256 curve)
# Format: JWK (JSON Web Key)
#
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone. Anyone with access to this key can forge
# signatures on HPKE distributions.
# This key is used by KDC to sign HPKE distributions (JWS signatures).
#
# Note: HPKE backends require TWO keys:
#   - X25519 key for encryption (kdc_hpke_priv_key)
#   - P-256 ECDSA key for signing (kdc_hpke_signing_key) - THIS FILE
#
# To use this keypair:
# 1. Add the following to your KDC config file (under 'kdc:' section):
#    kdc_hpke_signing_key: %s
# 2. Restart the KDC
#
# WARNING: If you generate a NEW signing key, distributions will have different signatures.
# Nodes will need the updated public key to verify signatures.
#
%s
`, generatedAt, keyID, hpkeSigningOutfile, prettyJSONBytes)

			// Write key file with secure permissions
			if err := os.WriteFile(hpkeSigningOutfile, []byte(keyContent), 0600); err != nil {
				log.Fatalf("Error writing HPKE signing key file: %v", err)
			}

			// Get absolute path for display
			absPath, err := filepath.Abs(hpkeSigningOutfile)
			if err != nil {
				absPath = hpkeSigningOutfile
			}

			fmt.Printf("✓ HPKE signing keypair generated successfully!\n")
			fmt.Printf("  KeyID:     %s\n", keyID)
			fmt.Printf("  File:      %s\n\n", absPath)
		}

		// Generate JOSE key if requested
		if genJose {
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

		// Conditionally add HPKE config step
		if genHpke {
			absPath, _ := filepath.Abs(hpkeOutfile)
			steps = append(steps, fmt.Sprintf("Add to your KDC config: kdc_hpke_priv_key: %s", absPath))
		}

		// Conditionally add JOSE config step
		if genJose {
			absPath, _ := filepath.Abs(joseOutfile)
			steps = append(steps, fmt.Sprintf("Add to your KDC config: kdc_jose_priv_key: %s", absPath))
		}

		// Always include restart and enrollment blob steps
		steps = append(steps, "Restart the KDC")

		// Determine enrollment blob message based on which keys were generated
		steps = append(steps, "Generate enrollment blobs (which will include the generated public keys)")

		// Print steps with sequential numbering
		for i, step := range steps {
			fmt.Printf("  %d. %s\n", i+1, step)
		}

		// Print reminder about key requirements
		fmt.Printf("\nNote: For full JWS(JWE) authenticated distributions:\n")
		fmt.Printf("  - JOSE: Single P-256 key for both encryption and signing\n")
		fmt.Printf("  - HPKE: TWO keys required (X25519 for encryption + P-256 ECDSA for signing)\n")
	},
}

func init() {
	KdcKeysCmd.AddCommand(kdcKeysListCmd, kdcKeysGenerateCmd)

	// Keys list command flags
	kdcKeysListCmd.Flags().String("hpke-file", "", "Path to HPKE private key file")
	kdcKeysListCmd.Flags().String("jose-file", "", "Path to JOSE private key file")

	// Keys generate command flags
	kdcKeysGenerateCmd.Flags().Bool("hpke", false, "Generate new HPKE encryption keypair")
	kdcKeysGenerateCmd.Flags().String("hpke-outfile", "", "Output file path for HPKE private key (default: ./kdc.hpke.privatekey)")
	kdcKeysGenerateCmd.Flags().Bool("hpke-signing", false, "Generate new HPKE signing keypair")
	kdcKeysGenerateCmd.Flags().String("hpke-signing-outfile", "", "Output file path for HPKE signing private key (default: ./kdc.hpke.signing.privatekey)")
	kdcKeysGenerateCmd.Flags().Bool("jose", false, "Generate new JOSE keypair")
	kdcKeysGenerateCmd.Flags().String("jose-outfile", "", "Output file path for JOSE private key (default: ./kdc.jose.privatekey)")
}
