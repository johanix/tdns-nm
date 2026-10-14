/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-kdc - Key Distribution Center daemon
 */

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gorilla/mux"
	//	"github.com/johanix/tdns-nm/tnm"
	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-nm/tnm/kdc"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeKdc
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := &tdns.Conf
	err := conf.MainInit(ctx, tdns.DefaultKdcCfgFile)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	// Parse KDC configuration section from config file
	// This must be done after MainInit (which calls ParseConfig) but before startKdc
	kdcConf, err := tnm.ParseKdcConfigFromFile(conf)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error parsing KDC config: %v", err))
	}

	apirouter, err := conf.SetupAPIRouter(ctx)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error setting up API router: %v", err))
	}

	// SIGHUP reload watcher
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				log.Printf("SIGHUP received - reload not yet implemented for KDC")
			}
		}
	}()

	// Initialize KDC (replaces conf.StartKdc())
	// Note: This will also register KDC API routes directly on apirouter
	err = startKdc(ctx, conf, kdcConf, apirouter)
	if err != nil {
		// Print error to stdout so user sees it immediately
		fmt.Fprintf(os.Stdout, "\n%s\n\n", err.Error())
		tdns.Shutdowner(conf, fmt.Sprintf("Error starting KDC: %v", err))
	}

	// Enter main loop
	conf.MainLoop(ctx, stop)
}

// startKdc initializes and starts all KDC subsystems
// This replaces the tdns.StartKdc() function but uses tdns-nm packages
func startKdc(ctx context.Context, conf *tdns.Config, kdcConf *tnm.KdcConf, apirouter *mux.Router) error {
	// Validate JOSE key configuration BEFORE initializing database
	// This is critical - KDC cannot function without a valid JOSE keypair
	if kdcConf.KdcJosePrivKey == "" {
		return fmt.Errorf(`FATAL: kdc_jose_priv_key is not configured in KDC config file.

The KDC requires a long-term JOSE (P-256) keypair to:
  - Encrypt enrollment confirmations sent to KRS nodes
  - Decrypt enrollment requests from KRS nodes
  - Sign and encrypt key distributions

To fix this:
  1. Generate a JOSE keypair using: kdc-cli keys generate --jose-outfile /path/to/kdc.jose.privatekey
  2. Add the following to your KDC config file (under 'kdc:' section):
     kdc_jose_priv_key: /path/to/kdc.jose.privatekey
  3. Restart the KDC

The key file will be created with appropriate permissions (0600).`)
	}

	// Try to load the JOSE keypair to validate it exists and is readable
	joseKeys, err := kdc.GetKdcJoseKeypair(kdcConf.KdcJosePrivKey)
	if err != nil {
		return fmt.Errorf(`FATAL: Failed to load JOSE keypair from %s: %v

The KDC cannot start without a valid JOSE keypair. This keypair is required to:
  - Encrypt enrollment confirmations sent to KRS nodes
  - Decrypt enrollment requests from KRS nodes
  - Sign and encrypt key distributions

To fix this:
  1. If the key file does not exist, generate a new JOSE keypair:
     kdc-cli keys generate --jose-outfile %s
  2. If the key file exists but cannot be read, check file permissions (should be 0600)
  3. Ensure the path in kdc_jose_priv_key in your KDC config is correct
  4. Restart the KDC

Note: If you generate a NEW keypair, you must regenerate all enrollment blobs that were
created with the old public key, as they will no longer be decryptable.`, kdcConf.KdcJosePrivKey, err, kdcConf.KdcJosePrivKey)
	}

	// Log successful key loading (key ID for verification)
	log.Printf("KDC: Loaded JOSE keypair from %s (key id: %s)", kdcConf.KdcJosePrivKey, kdc.GenerateKeyID("jose", joseKeys.PublicKeyBytes))

	kdcDB, err := kdc.NewKdcDB(kdcConf.Database.Type, kdcConf.Database.DSN, kdcConf)
	if err != nil {
		return fmt.Errorf("failed to initialize KDC database: %v", err)
	}

	// Initialize catalog zone if configured (auto-generate on startup)
	if err := kdc.InitializeCatalogZone(ctx, kdcDB, kdcConf); err != nil {
		return fmt.Errorf("failed to initialize catalog zone: %v", err)
	}

	// Register KDC API routes directly on the router
	// Pass conf as map to avoid circular import, and pass ping handler
	confMap := map[string]interface{}{
		"ApiServer": map[string]interface{}{
			"ApiKey":    conf.ApiServer.ApiKey,
			"Addresses": conf.ApiServer.Addresses,
		},
		"DnsEngine": map[string]interface{}{
			"Addresses": conf.Listeners.Addresses,
		},
		"KdcConf": kdcConf,
	}
	// Call SetupKdcAPIRoutes directly on the router (not via RegisterAPIRoute)
	// because SetupAPIRouter has already been called and returned
	kdc.SetupKdcAPIRoutes(apirouter, kdcDB, confMap, tdns.APIping(conf))

	// Start API dispatcher (this is a TDNS internal engine, not registered)
	go func() {
		log.Printf("TDNS %s (%s): starting: APIdispatcher", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
		if err := tdns.APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
			log.Printf("Error from APIdispatcher engine: %v", err)
		}
	}()

	// Register debug query handler FIRST (for all queries) - logs all queries before processing
	// This is optional - only register if debug mode is enabled
	if tdns.Globals.Debug {
		if err := tdns.RegisterDebugQueryHandler(); err != nil {
			return fmt.Errorf("failed to register debug query handler: %v", err)
		}
		log.Printf("KDC: Registered debug query handler")
	}

	// Register query handlers for KDC-specific query types using the new registration API
	// This replaces the old channel-based approach
	kdcQueryHandler := func(ctx context.Context, dqr *tdns.DnsQueryRequest) error {
		if tdns.Globals.Debug {
			log.Printf("KDC: QueryHandler invoked (qname=%s, qtype=%s)", dqr.Qname, dns.TypeToString[dqr.Qtype])
		}
		// Convert DnsQueryRequest to kdc.KdcQueryRequest
		kdcReq := &kdc.KdcQueryRequest{
			ResponseWriter: dqr.ResponseWriter,
			Msg:            dqr.Msg,
			Qname:          dqr.Qname,
			Qtype:          dqr.Qtype,
			Options:        dqr.Options,
		}
		// Call KDC handler (will return ErrNotHandled for unsupported qtypes)
		return kdc.HandleKdcQuery(ctx, kdcReq, kdcDB, kdcConf)
	}

	// Register handlers for each qtype that KDC handles
	if err := tdns.RegisterQueryHandler(core.TypeCHUNK, kdcQueryHandler); err != nil {
		return fmt.Errorf("failed to register CHUNK handler: %v", err)
	}
	log.Printf("KDC: Registered query handler for CHUNK")

	// Register default query handler for zone-based queries (e.g., catalog zone)
	// This is needed because KDC doesn't have zones in config, but may have programmatically added zones
	// The default handler serves zones from the Zones map (including programmatically added ones)
	if err := tdns.RegisterQueryHandler(0, tdns.DefaultQueryHandler); err != nil {
		return fmt.Errorf("failed to register default query handler: %v", err)
	}
	log.Printf("KDC: Registered default zone-based query handler")

	// Register debug NOTIFY handler FIRST (for all NOTIFYs) - logs all NOTIFYs before processing
	// This is optional - only register if debug mode is enabled
	if tdns.Globals.Debug {
		if err := tdns.RegisterDebugNotifyHandler(); err != nil {
			return fmt.Errorf("failed to register debug NOTIFY handler: %v", err)
		}
		log.Printf("KDC: Registered debug NOTIFY handler")
	}

	// Register KDC NOTIFY handler (handles confirmation NOTIFYs from KRS)
	// Only handles MANIFEST NOTIFYs
	kdcNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
		if tdns.Globals.Debug {
			log.Printf("KDC: NotifyHandler callback invoked (qname=%s)", dnr.Qname)
		}
		// Call KDC NOTIFY handler
		return kdc.HandleKdcNotify(ctx, dnr.Msg, dnr.Qname, dnr.ResponseWriter, kdcDB, kdcConf)
	}
	if err := tdns.RegisterNotifyHandler(core.TypeCHUNK, kdcNotifyHandler); err != nil {
		return fmt.Errorf("failed to register CHUNK NOTIFY handler: %v", err)
	}
	log.Printf("KDC: Registered NOTIFY handler for CHUNK")

	// Register KDC enrollment UPDATE handler (handles enrollment DNS UPDATE requests)
	// Matches UPDATEs with name pattern _enroll.*
	enrollmentMatcher := func(dur *tdns.DnsUpdateRequest) bool {
		// Check if any RR in the UPDATE section has a name starting with "_enroll."
		for _, rr := range dur.Msg.Ns {
			if strings.HasPrefix(rr.Header().Name, "_enroll.") {
				return true
			}
		}
		return false
	}

	enrollmentUpdateHandler := func(ctx context.Context, dur *tdns.DnsUpdateRequest) error {
		if tdns.Globals.Debug {
			log.Printf("KDC: EnrollmentUpdateHandler invoked (qname=%s)", dur.Qname)
		}
		// Call KDC enrollment handler
		return kdc.HandleEnrollmentUpdate(ctx, dur, kdcDB, kdcConf)
	}

	if err := tdns.RegisterUpdateHandler(enrollmentMatcher, enrollmentUpdateHandler); err != nil {
		return fmt.Errorf("failed to register enrollment UPDATE handler: %v", err)
	}
	log.Printf("KDC: Registered enrollment UPDATE handler for _enroll.* pattern")

	// Register engines using the registration API
	if err := tdns.RegisterEngine("DnsEngine", func(ctx context.Context) error {
		return tdns.DnsEngine(ctx, conf)
	}); err != nil {
		return fmt.Errorf("failed to register DnsEngine: %v", err)
	}

	if err := tdns.RegisterEngine("KeyStateWorker", func(ctx context.Context) error {
		return kdc.KeyStateWorker(ctx, kdcDB, kdcConf)
	}); err != nil {
		return fmt.Errorf("failed to register KeyStateWorker: %v", err)
	}

	// Start all registered engines (including DnsEngine and KeyStateWorker)
	tdns.StartRegisteredEngines(ctx)

	log.Printf("TDNS %s (%s): KDC started successfully", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
	return nil
}
