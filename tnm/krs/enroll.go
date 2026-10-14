/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Enrollment client implementation for KRS
 */

package krs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-nm/tnm/kdc"
	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // Auto-register JOSE backend
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// BootstrapConfig represents the configuration generated during bootstrap
type BootstrapConfig struct {
	Service   ServiceConfig    `yaml:"service"`
	Log       LogConfig        `yaml:"log"`
	ApiServer ApiServerConfig  `yaml:"apiserver"`
	DnsEngine DnsEngineConfig  `yaml:"listeners"` // tdns listeners; KRS merges them into its dnsengine
	Krs       KrsBootstrapConf `yaml:"krs"`
}

type ServiceConfig struct {
	Name    string `yaml:"name"`
	Verbose bool   `yaml:"verbose"`
	Debug   bool   `yaml:"debug"`
}

type LogConfig struct {
	File string `yaml:"file"`
}

type ApiServerConfig struct {
	UseTLS    bool     `yaml:"usetls,omitempty"` // Always true - omitted from config (defaults to true)
	Addresses []string `yaml:"addresses"`
	ApiKey    string   `yaml:"apikey"`
	CertFile  string   `yaml:"certfile"`
	KeyFile   string   `yaml:"keyfile"`
	BaseURL   string   `yaml:"baseurl,omitempty"` // Base URL for API client (used by krs-cli, not by tdns-krs)
}

type DnsEngineConfig struct {
	Addresses  []string `yaml:"addresses"`
	Transports []string `yaml:"transports"`
	CertFile   string   `yaml:"certfile,omitempty"`
	KeyFile    string   `yaml:"keyfile,omitempty"`
}

type KrsBootstrapConf struct {
	Database        tnm.KrsDatabaseConf `yaml:"database"`
	Node            tnm.NodeConf        `yaml:"node"`
	ControlZone     string              `yaml:"control_zone"`
	SupportedCrypto []string            `yaml:"supported_crypto"` // List of supported crypto backends (e.g., ["jose"])
}

// RunEnroll performs the complete enrollment process
// blobFile: Path to enrollment blob file
// Parameters:
//   - blobFile: Path to enrollment blob file
//   - configDir: Directory for config and key files
//   - notifyAddress: IP:port where KDC should send NOTIFY messages
//   - cryptoBackend: Optional crypto backend ("jose"), empty string for the default (JOSE)
//   - apiAddress: Optional API server address (default: "127.0.0.1:8990")
//   - dbPath: Optional database file path (default: "/var/lib/tdns/krs.db")
//   - logFile: Optional log file path (default: "/var/log/tdns/tdns-krs.log")
//
// Returns: error
func RunEnroll(blobFile string, configDir string, notifyAddress string, cryptoBackend string, apiAddress string, dbPath string, logFile string) error {
	// 1. Parse enrollment blob file
	blob, err := kdc.ParseEnrollmentBlob(blobFile)
	if err != nil {
		return fmt.Errorf("failed to parse enrollment blob: %v", err)
	}

	log.Printf("KRS: Parsed enrollment blob for node %s", blob.NodeID)

	// 2. The blob must carry the KDC JOSE public key
	if cryptoBackend != "" && cryptoBackend != "jose" {
		return fmt.Errorf("invalid crypto backend: %s (must be 'jose')", cryptoBackend)
	}
	if blob.KdcJosePubKey == "" {
		return fmt.Errorf("enrollment blob does not contain the KDC JOSE public key")
	}

	// Generate the node's JOSE keypair
	joseBackend, err := crypto.GetBackend("jose")
	if err != nil {
		return fmt.Errorf("failed to get JOSE backend: %v", err)
	}
	josePrivKey, josePubKey, err := joseBackend.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate JOSE keypair: %v", err)
	}
	// Serialize JOSE keys
	josePrivKeyBytes, err := joseBackend.SerializePrivateKey(josePrivKey)
	if err != nil {
		return fmt.Errorf("failed to serialize JOSE private key: %v", err)
	}
	josePubKeyBytes, err := joseBackend.SerializePublicKey(josePubKey)
	if err != nil {
		return fmt.Errorf("failed to serialize JOSE public key: %v", err)
	}
	supportedCrypto := []string{"jose"}
	log.Printf("KRS: Generated JOSE keypair")

	// 3. Generate SIG(0) keypair (Ed25519)
	sig0Key := new(dns.KEY)
	sig0Key.Algorithm = dns.ED25519
	sig0Key.Flags = 256 // SIG(0) key flag
	sig0Key.Protocol = 3
	sig0Key.Header().Name = blob.NodeID
	sig0Key.Header().Rrtype = dns.TypeKEY
	sig0Key.Header().Class = dns.ClassINET
	sig0Key.Header().Ttl = 3600

	sig0PrivKey, err := sig0Key.Generate(256)
	if err != nil {
		return fmt.Errorf("failed to generate SIG(0) keypair: %v", err)
	}

	// Get SIG(0) public key as DNSKEY string
	sig0PubKeyStr := sig0Key.String()
	log.Printf("KRS: Generated SIG(0) keypair")

	// 4. Create enrollment request
	// Use the provided notify address (from command line flag)
	enrollmentReq := map[string]interface{}{
		"sig0_pubkey":    sig0PubKeyStr,
		"auth_token":     blob.Token,
		"timestamp":      time.Now().Format(time.RFC3339),
		"notify_address": notifyAddress,
		"jose_pubkey":    string(josePubKeyBytes), // JWK JSON
	}

	reqJSON, err := json.Marshal(enrollmentReq)
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment request: %v", err)
	}

	// 5. Encrypt enrollment request to the KDC JOSE public key
	encryptionBackend := "jose"
	kdcPubKeyData, err := base64.StdEncoding.DecodeString(blob.KdcJosePubKey)
	if err != nil {
		return fmt.Errorf("failed to decode KDC JOSE public key: %v", err)
	}

	// Use shared encryption function (operation-agnostic, crypto-agnostic)
	encryptedReq, _, err := tnm.EncryptPayload(reqJSON, kdcPubKeyData, encryptionBackend, supportedCrypto, "enrollment request to KDC")
	if err != nil {
		return fmt.Errorf("failed to encrypt enrollment request: %v", err)
	}
	log.Printf("KRS: Encrypted enrollment request using %s backend (length: %d)", encryptionBackend, len(encryptedReq))

	// 6. Create CHUNK record with encrypted enrollment request
	// Check for integer overflow before converting to uint16
	if len(encryptedReq) > math.MaxUint16 {
		return fmt.Errorf("encrypted enrollment request too large: %d bytes (max: %d)", len(encryptedReq), math.MaxUint16)
	}
	chunk := &core.CHUNK{
		Format:     core.FormatJSON,
		HMACLen:    0, // No HMAC for enrollment
		HMAC:       nil,
		Sequence:   0, // Sequence=0 indicates enrollment/manifest chunk
		Total:      0, // Total=0 for enrollment (no data chunks)
		DataLength: uint16(len(encryptedReq)),
		Data:       encryptedReq,
	}

	chunkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("_enroll.%s", blob.ControlZone),
			Rrtype: core.TypeCHUNK,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Data: chunk,
	}

	// 7. Create DNS UPDATE message
	updateMsg, err := tdns.CreateUpdate(blob.ControlZone, []dns.RR{chunkRR}, []dns.RR{})
	if err != nil {
		return fmt.Errorf("failed to create DNS UPDATE: %v", err)
	}

	// 8. Sign UPDATE with SIG(0)
	// Convert Ed25519 private key to PEM format for PrepareKeyCache
	sig0PrivKeyPEM, err := tdns.PrivateKeyToPEM(sig0PrivKey)
	if err != nil {
		return fmt.Errorf("failed to convert SIG(0) key to PEM: %v", err)
	}

	// Create PrivateKeyCache using PrepareKeyCache
	pkc, err := tdns.PrepareKeyCache(sig0PrivKeyPEM, sig0PubKeyStr)
	if err != nil {
		return fmt.Errorf("failed to prepare SIG(0) key cache: %v", err)
	}

	// Create Sig0ActiveKeys structure for signing
	sak := &tdns.Sig0ActiveKeys{
		Keys: []*tdns.PrivateKeyCache{pkc},
	}

	signedMsg, err := tdns.SignMsg(*updateMsg, blob.ControlZone, sak)
	if err != nil {
		return fmt.Errorf("failed to sign DNS UPDATE: %v", err)
	}
	log.Printf("KRS: Signed DNS UPDATE with SIG(0)")

	// 9. Send UPDATE to KDC
	// Validate enrollment address is present
	if blob.KdcEnrollmentAddress == "" {
		return fmt.Errorf("enrollment blob is missing kdc_enrollment_address field - the KDC configuration is incomplete. Please regenerate the enrollment blob with a properly configured KDC (kdc_enrollment_address must be set in KDC config)")
	}

	// Parse KDC enrollment address (IP:port)
	host, port, err := net.SplitHostPort(blob.KdcEnrollmentAddress)
	if err != nil {
		return fmt.Errorf("invalid KDC enrollment address format '%s': %v (expected format: IP:port or hostname:port)", blob.KdcEnrollmentAddress, err)
	}

	// Resolve hostname if needed
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("failed to resolve KDC address %s: %v", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses found for KDC host %s", host)
	}

	kdcAddr := net.JoinHostPort(addrs[0], port)
	log.Printf("KRS: Sending enrollment UPDATE to %s", kdcAddr)

	client := new(dns.Client)
	client.Timeout = 10 * time.Second

	resp, _, err := client.Exchange(signedMsg, kdcAddr)
	if err != nil {
		return fmt.Errorf("failed to send DNS UPDATE: %v", err)
	}

	// 10. Extract and process response from CHUNK EDNS(0) option
	// KDC always returns a CHUNK option with either success or error details
	opt := resp.IsEdns0()
	if opt == nil {
		return fmt.Errorf("no EDNS(0) option in response (expected CHUNK option with enrollment response)")
	}

	chunkOpt, found := edns0.ExtractChunkOption(opt)
	if !found {
		return fmt.Errorf("no CHUNK EDNS(0) option in response (expected CHUNK option with enrollment response)")
	}

	contentType, encryptedData, err := edns0.ParseEnrollmentConfirmation(chunkOpt)
	if err != nil {
		return fmt.Errorf("failed to parse enrollment response: %v", err)
	}

	if contentType != edns0.CHUNKContentTypeEnrollmentConfirmation {
		return fmt.Errorf("unexpected content type in response: %d (expected %d)", contentType, edns0.CHUNKContentTypeEnrollmentConfirmation)
	}

	// 11. Decrypt response (may be encrypted or unencrypted)
	decryptedData, err := joseBackend.Decrypt(josePrivKey, encryptedData)
	if err != nil {
		// Decryption failed - might be unencrypted error message
		if resp.Rcode != dns.RcodeSuccess {
			log.Printf("KRS: Failed to decrypt response (may be unencrypted error): %v", err)
			decryptedData = encryptedData // Use as-is, might be unencrypted error
		} else {
			return fmt.Errorf("failed to decrypt enrollment confirmation with JOSE: %v (RCODE was SUCCESS, so response should be encrypted)", err)
		}
	}

	var confirmation edns0.EnrollmentConfirmation
	if err := json.Unmarshal(decryptedData, &confirmation); err != nil {
		return fmt.Errorf("failed to parse response JSON: %v", err)
	}

	// Check if this is an error response
	if confirmation.Status == "error" {
		errorMsg := confirmation.ErrorMessage
		if errorMsg == "" {
			errorMsg = "Unknown error"
		}
		return fmt.Errorf("enrollment failed: %s (RCODE: %s)", errorMsg, dns.RcodeToString[resp.Rcode])
	}

	// Validate success confirmation
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("enrollment UPDATE failed with RCODE %s (but received success confirmation - this is unexpected)", dns.RcodeToString[resp.Rcode])
	}

	if confirmation.Status != "success" {
		return fmt.Errorf("enrollment confirmation status: %s (error: %s)", confirmation.Status, confirmation.ErrorMessage)
	}

	if confirmation.NodeID != blob.NodeID {
		return fmt.Errorf("confirmation node ID mismatch: expected %s, got %s", blob.NodeID, confirmation.NodeID)
	}

	log.Printf("KRS: Enrollment confirmation received and validated for node %s", confirmation.NodeID)

	// 12. Write key files
	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	nodeIDNoDot := strings.TrimSuffix(blob.NodeID, ".")
	var joseKeyFileAbs string
	var sig0KeyFileAbs string
	var certFileAbs string
	var keyFileAbs string

	// Write JOSE private key
	{
		joseKeyFile := filepath.Join(configDir, fmt.Sprintf("%s.jose.privatekey", nodeIDNoDot))
		// Parse JSON to pretty-print it
		var joseKeyJSON interface{}
		if err := json.Unmarshal(josePrivKeyBytes, &joseKeyJSON); err != nil {
			return fmt.Errorf("failed to parse JOSE private key JSON: %v", err)
		}
		joseKeyPretty, err := json.MarshalIndent(joseKeyJSON, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format JOSE private key JSON: %v", err)
		}
		joseKeyContent := fmt.Sprintf(`# KRS JOSE Private Key (P-256)
# Generated: %s
# Algorithm: P-256 (ECDSA for JWE with ECDH-ES)
# Key Size: 256 bits (P-256 curve)
# Format: JWK (JSON Web Key)
#
# WARNING: This is a PRIVATE KEY. Keep it secret and secure!
# Do not share this key with anyone.
#
%s
`, time.Now().Format(time.RFC3339), string(joseKeyPretty))

		if err := os.WriteFile(joseKeyFile, []byte(joseKeyContent), 0600); err != nil {
			return fmt.Errorf("failed to write JOSE private key: %v", err)
		}
		log.Printf("KRS: Wrote JOSE private key to %s", joseKeyFile)

		// Make JOSE key file path absolute
		if abs, absErr := filepath.Abs(joseKeyFile); absErr == nil {
			joseKeyFileAbs = abs
		} else {
			joseKeyFileAbs = joseKeyFile // Fallback to relative if absolute fails
		}
	}

	var kdcJosePubKeyFileAbs string

	// Write KDC JOSE public key to disk
	{
		kdcJosePubKeyBytes, err := base64.StdEncoding.DecodeString(blob.KdcJosePubKey)
		if err != nil {
			return fmt.Errorf("failed to decode KDC JOSE public key: %v", err)
		}
		// Parse and pretty-print JWK JSON
		var kdcJosePubKeyJSON interface{}
		if err := json.Unmarshal(kdcJosePubKeyBytes, &kdcJosePubKeyJSON); err != nil {
			return fmt.Errorf("failed to parse KDC JOSE public key JSON: %v", err)
		}
		kdcJosePubKeyPretty, err := json.MarshalIndent(kdcJosePubKeyJSON, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format KDC JOSE public key JSON: %v", err)
		}
		kdcJosePubKeyFile := filepath.Join(configDir, "kdc.jose.pubkey")
		kdcJosePubKeyContent := fmt.Sprintf(`# KDC JOSE Public Key
# Received during enrollment: %s
# Algorithm: P-256 (ECDSA for JWE with ECDH-ES)
# Format: JWK (JSON Web Key)
#
%s
`, time.Now().Format(time.RFC3339), string(kdcJosePubKeyPretty))
		if err := os.WriteFile(kdcJosePubKeyFile, []byte(kdcJosePubKeyContent), 0644); err != nil {
			return fmt.Errorf("failed to write KDC JOSE public key: %v", err)
		}
		log.Printf("KRS: Wrote KDC JOSE public key to %s", kdcJosePubKeyFile)

		// Make KDC JOSE public key file path absolute
		if abs, absErr := filepath.Abs(kdcJosePubKeyFile); absErr == nil {
			kdcJosePubKeyFileAbs = abs
		} else {
			kdcJosePubKeyFileAbs = kdcJosePubKeyFile
		}
	}

	// Write SIG(0) private key (PEM format)
	sig0KeyFile := filepath.Join(configDir, fmt.Sprintf("%s.sig0.privatekey", nodeIDNoDot))
	// Reuse sig0PrivKeyPEM from earlier (already converted to PEM for PrepareKeyCache)
	if err := os.WriteFile(sig0KeyFile, []byte(sig0PrivKeyPEM), 0600); err != nil {
		return fmt.Errorf("failed to write SIG(0) private key: %v", err)
	}
	log.Printf("KRS: Wrote SIG(0) private key to %s", sig0KeyFile)

	// Make SIG(0) key file path absolute
	if abs, absErr := filepath.Abs(sig0KeyFile); absErr == nil {
		sig0KeyFileAbs = abs
	} else {
		sig0KeyFileAbs = sig0KeyFile
	}

	// Set defaults for optional parameters (before generating API certs)
	if apiAddress == "" {
		apiAddress = "127.0.0.1:8990"
	}
	if dbPath == "" {
		dbPath = "/var/lib/tdns/krs.db"
	}
	if logFile == "" {
		logFile = "/var/log/tdns/tdns-krs.log"
	}

	// 13. Generate API certs (if needed)
	// Parse apiAddress to extract host for certificate SANs
	certFile, keyFile, err := generateAPICerts(configDir, blob.NodeID, apiAddress)
	if err != nil {
		return fmt.Errorf("failed to generate API certificates: %v", err)
	}
	log.Printf("KRS: Generated API certificates: %s, %s", certFile, keyFile)

	// Make cert and key file paths absolute
	if abs, absErr := filepath.Abs(certFile); absErr == nil {
		certFileAbs = abs
	} else {
		certFileAbs = certFile
	}
	if abs, absErr := filepath.Abs(keyFile); absErr == nil {
		keyFileAbs = abs
	} else {
		keyFileAbs = keyFile
	}

	// 14. Ensure database directory exists (before generating config)

	// The database DSN is configurable, so we check it here
	if err := tnm.EnsureDatabaseDirectory(dbPath); err != nil {
		return fmt.Errorf("failed to ensure database directory: %v", err)
	}
	log.Printf("KRS: Database directory ready: %s", filepath.Dir(dbPath))

	// 15. Generate config file
	configFile := filepath.Join(configDir, "tdns-krs.yaml")
	// Construct baseurl with /api/v1 path (API always uses TLS, no trailing slash)
	baseURL := fmt.Sprintf("https://%s/api/v1", apiAddress)

	// Generate API key (fail fast on crypto/rand errors)
	apiKey, err := generateApiKey()
	if err != nil {
		return fmt.Errorf("failed to generate API key: %v", err)
	}

	config := BootstrapConfig{
		Service: ServiceConfig{
			Name:    "TDNS-KRS",
			Verbose: true,
			Debug:   false,
		},
		Log: LogConfig{
			File: logFile,
		},
		ApiServer: ApiServerConfig{
			// UseTLS not set - omitted from config (defaults to true in tdns)
			Addresses: []string{apiAddress},
			ApiKey:    apiKey,
			CertFile:  certFileAbs,
			KeyFile:   keyFileAbs,
			BaseURL:   baseURL, // Base URL for krs-cli API client (includes /api/v1/ path)
		},
		DnsEngine: DnsEngineConfig{
			Addresses:  []string{notifyAddress}, // Use notify address as primary DNS engine address
			Transports: []string{"do53"},
			CertFile:   certFileAbs,
			KeyFile:    keyFileAbs,
		},
		Krs: KrsBootstrapConf{
			Database: tnm.KrsDatabaseConf{
				DSN: dbPath,
			},
			Node: tnm.NodeConf{
				ID:                  blob.NodeID,
				LongTermJosePrivKey: joseKeyFileAbs,
				KdcAddress:          blob.KdcEnrollmentAddress,
				KdcJosePubKey:       kdcJosePubKeyFileAbs,
			},
			ControlZone:     blob.ControlZone,
			SupportedCrypto: supportedCrypto,
		},
	}

	configYAML, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Add header comment with generation timestamp
	headerComment := fmt.Sprintf("# This configuration file was auto-generated by krs-cli enroll\n# Generated at: %s\n#\n# WARNING: This file is auto-generated. Manual edits may be overwritten.\n# To regenerate, run: krs-cli enroll --package <blobfile> --configdir <dir>\n#\n", time.Now().Format(time.RFC3339))
	configWithHeader := []byte(headerComment + string(configYAML))

	// Write config file with restrictive permissions (0600) since it contains sensitive API keys
	if err := os.WriteFile(configFile, configWithHeader, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	log.Printf("KRS: Wrote configuration file to %s", configFile)

	// 16. Success message
	fmt.Printf("\n")
	fmt.Printf("✓ Enrollment completed successfully!\n")
	fmt.Printf("\n")
	fmt.Printf("Configuration written to: %s\n", configDir)
	fmt.Printf("  - Config file: %s\n", configFile)
	fmt.Printf("  - JOSE key: %s\n", joseKeyFileAbs)
	fmt.Printf("  - SIG(0) key: %s\n", sig0KeyFileAbs)
	fmt.Printf("  - API cert: %s\n", certFileAbs)
	fmt.Printf("  - API TLS key: %s\n", keyFileAbs)
	fmt.Printf("  - API key (config): stored in %s (apiserver.apikey)\n", configFile)
	fmt.Printf("  - KDC JOSE pubkey: %s\n", kdcJosePubKeyFileAbs)
	fmt.Printf("\n")
	fmt.Printf("Node ID: %s\n", confirmation.NodeID)
	fmt.Printf("\n")
	fmt.Printf("Next steps:\n")
	fmt.Printf("  1. Review the configuration file: %s\n", configFile)
	fmt.Printf("  2. Adjust settings as needed (database path, addresses, etc.)\n")
	fmt.Printf("  3. Start tdns-krs with: krs-cli daemon start\n")
	fmt.Printf("\n")

	return nil
}

// generateAPICerts generates a self-signed certificate for API server
func generateAPICerts(configDir string, nodeID string, apiAddress string) (certFile string, keyFile string, err error) {
	// Create certs subdirectory
	certsDir := filepath.Join(configDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create certs directory: %v", err)
	}

	// Parse apiAddress to extract host for certificate SANs
	host, _, err := net.SplitHostPort(apiAddress)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse apiAddress %q: %v", apiAddress, err)
	}

	// Determine certificate SANs based on host
	var ipAddresses []net.IP
	var dnsNames []string
	var commonName string

	// Try to parse as IP address
	if ip := net.ParseIP(host); ip != nil {
		// It's an IP address
		ipAddresses = []net.IP{ip}
		commonName = host
	} else {
		// It's a hostname
		dnsNames = []string{host}
		commonName = host
		// Also include localhost variants for compatibility
		ipAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		dnsNames = append(dnsNames, "localhost")
	}

	// Generate private key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template (random serial)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate certificate serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TDNS-KRS"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ipAddresses,
		DNSNames:    dnsNames,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %v", err)
	}

	// Sanitize host for use in filename (replace colons and other special chars)
	sanitizedHost := strings.ReplaceAll(host, ":", "_")
	sanitizedHost = strings.ReplaceAll(sanitizedHost, ".", "_")
	if sanitizedHost == "" {
		sanitizedHost = "localhost" // Fallback if host is empty
	}

	// Write certificate (PEM format)
	certFile = filepath.Join(certsDir, sanitizedHost+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write certificate: %v", err)
	}

	// Write private key (PEM format)
	keyFile = filepath.Join(certsDir, sanitizedHost+".key")
	keyPEM, err := tdns.PrivateKeyToPEM(privKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert key to PEM: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte(keyPEM), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write private key: %v", err)
	}

	return certFile, keyFile, nil
}

// generateApiKey generates a random API key
// Returns the hex-encoded 64-character API key, or an error if crypto/rand fails
func generateApiKey() (string, error) {
	// Generate 32 random bytes and encode as hex
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random API key: %v", err)
	}
	return hex.EncodeToString(key), nil
}
