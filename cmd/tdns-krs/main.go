/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-krs - Key Receiving Service daemon (edge receiver for HPKE key distribution)
 */

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	tnm "github.com/johanix/tdns-nm/tnm"
	"github.com/johanix/tdns-nm/tnm/krs"
	"github.com/johanix/tdns-transport/v2/hpke"
	tdns "github.com/johanix/tdns/v2"
)

func main() {
	tdns.Globals.App.Type = tdns.AppTypeKrs
	tdns.Globals.App.Version = appVersion
	tdns.Globals.App.Name = appName
	tdns.Globals.App.Date = appDate

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conf := &tdns.Conf
	err := conf.MainInit(ctx, tdns.DefaultKrsCfgFile)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error initializing TDNS: %v", err))
	}

	// Parse KRS configuration section from config file
	// This must be done after MainInit (which calls ParseConfig) but before startKrs
	krsConf, err := tnm.ParseKrsConfigFromFile(conf)
	if err != nil {
		tdns.Shutdowner(conf, fmt.Sprintf("Error parsing KRS config: %v", err))
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
				log.Printf("SIGHUP received - reload not yet implemented for KRS")
			}
		}
	}()

	// Initialize KRS (replaces conf.StartKrs())
	err = startKrs(ctx, conf, krsConf, apirouter)
	if err != nil {
		// Print error to stdout/stderr for visibility
		fmt.Fprintf(os.Stderr, "FATAL: Error starting KRS: %v\n", err)
		tdns.Shutdowner(conf, fmt.Sprintf("Error starting KRS: %v", err))
	}

	// Enter main loop
	conf.MainLoop(ctx, stop)
}

// startKrs initializes and starts all KRS subsystems
// This replaces the tdns.StartKrs() function but uses tdns-nm packages
func startKrs(ctx context.Context, conf *tdns.Config, krsConf *tnm.KrsConf, apirouter *mux.Router) error {
	// Initialize KRS database
	krsDB, err := krs.NewKrsDB(krsConf.Database.DSN)
	if err != nil {
		// Return detailed error message (already includes helpful instructions)
		return fmt.Errorf("failed to initialize KRS database: %v", err)
	}

	// Determine which crypto backends are supported
	// If SupportedCrypto is empty, infer from configured key paths
	// Otherwise, honor the explicit SupportedCrypto list
	hasHpke := false
	hasJose := false
	if len(krsConf.SupportedCrypto) == 0 {
		// Infer from key paths when SupportedCrypto is not specified
		if krsConf.Node.LongTermHpkePrivKey != "" {
			hasHpke = true
		}
		if krsConf.Node.LongTermJosePrivKey != "" {
			hasJose = true
		}
	} else {
		// Honor explicit SupportedCrypto list
		for _, backend := range krsConf.SupportedCrypto {
			if backend == "hpke" {
				hasHpke = true
			}
			if backend == "jose" {
				hasJose = true
			}
		}
	}

	// Load and validate keys only for configured backends
	var hpkePubKey []byte
	var hpkePrivKey []byte

	if hasHpke {
		// Validate HPKE key is configured
		if krsConf.Node.LongTermHpkePrivKey == "" {
			return fmt.Errorf("HPKE private key not configured (long_term_hpke_priv_key is empty) but HPKE is in supported_crypto list. Either add the key path to the config or remove 'hpke' from supported_crypto")
		}

		// Load HPKE private key using shared helper
		privKey, err := tnm.LoadPrivateKey(krsConf.Node.LongTermHpkePrivKey)
		if err != nil {
			return fmt.Errorf("failed to load HPKE long-term private key from %s: %v", krsConf.Node.LongTermHpkePrivKey, err)
		}

		// Derive public key from private key
		pubKey, err := hpke.DerivePublicKey(privKey)
		if err != nil {
			return fmt.Errorf("failed to derive HPKE public key from private key in %s: %v", krsConf.Node.LongTermHpkePrivKey, err)
		}

		hpkePubKey = pubKey
		hpkePrivKey = privKey
		log.Printf("KRS: Loaded HPKE keypair from %s", krsConf.Node.LongTermHpkePrivKey)
	}

	if hasJose {
		// Validate JOSE key is configured
		if krsConf.Node.LongTermJosePrivKey == "" {
			return fmt.Errorf("JOSE private key not configured (long_term_jose_priv_key is empty) but JOSE is in supported_crypto list. Either add the key path to the config or remove 'jose' from supported_crypto")
		}

		// Validate JOSE key file exists and is readable
		if _, err := os.Stat(krsConf.Node.LongTermJosePrivKey); err != nil {
			return fmt.Errorf("failed to access JOSE long-term private key file %s: %v", krsConf.Node.LongTermJosePrivKey, err)
		}

		log.Printf("KRS: JOSE keypair configured at %s (will be loaded on demand)", krsConf.Node.LongTermJosePrivKey)
	}

	// Validate at least one backend is configured
	if !hasHpke && !hasJose {
		return fmt.Errorf("no crypto backends configured. Either set supported_crypto in config, or configure at least one of long_term_hpke_priv_key or long_term_jose_priv_key")
	}

	// Store node config in database (HPKE keys are optional for JOSE-only nodes)
	nodeConfig := &krs.NodeConfig{
		ID:                  krsConf.Node.ID,
		LongTermHpkePubKey:  hpkePubKey,  // nil for JOSE-only nodes
		LongTermHpkePrivKey: hpkePrivKey, // nil for JOSE-only nodes
		KdcAddress:          krsConf.Node.KdcAddress,
		ControlZone:         krsConf.ControlZone,
		RegisteredAt:        time.Now(),
		LastSeen:            time.Now(),
	}
	if err := krsDB.SetNodeConfig(nodeConfig); err != nil {
		return fmt.Errorf("failed to store node config: %v", err)
	}

	// Register KRS API routes directly on the router
	// Pass conf as map to avoid circular import, and pass ping handler
	confMap := map[string]interface{}{
		"ApiServer": map[string]interface{}{
			"ApiKey":    conf.ApiServer.ApiKey,
			"Addresses": conf.ApiServer.Addresses,
		},
	}
	// Call SetupKrsAPIRoutes directly on the router (not via RegisterAPIRoute)
	// because SetupAPIRouter has already been called and returned
	krs.SetupKrsAPIRoutes(apirouter, krsDB, krsConf, confMap, tdns.APIping(conf))
	log.Printf("KRS: API routes setup")

	// Start API dispatcher
	go func() {
		log.Printf("TDNS %s (%s): starting: APIdispatcher", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
		if err := tdns.APIdispatcher(conf, apirouter, conf.Internal.APIStopCh); err != nil {
			log.Printf("Error from APIdispatcher engine: %v", err)
		}
	}()

	log.Printf("API dispatcher started")

	// Register debug query handler FIRST (for all queries) - logs all queries before processing
	// This is optional - only register if debug mode is enabled
	if tdns.Globals.Debug {
		if err := tdns.RegisterDebugQueryHandler(); err != nil {
			return fmt.Errorf("failed to register debug query handler: %v", err)
		}
		log.Printf("KRS: Registered debug query handler")
	}

	// Register debug NOTIFY handler FIRST (for all NOTIFYs) - logs all NOTIFYs before processing
	// This is optional - only register if debug mode is enabled
	if tdns.Globals.Debug {
		if err := tdns.RegisterDebugNotifyHandler(); err != nil {
			return fmt.Errorf("failed to register debug NOTIFY handler: %v", err)
		}
		log.Printf("KRS: Registered debug NOTIFY handler")
	}

	// Register KRS NOTIFY handler (handles all NOTIFYs for control zone and distributions)
	// KRS handles NOTIFYs for any qtype, so we register with qtype=0 (all NOTIFYs)
	krsNotifyHandler := func(ctx context.Context, dnr *tdns.DnsNotifyRequest) error {
		return krs.HandleKrsNotify(ctx, dnr, krsDB, krsConf)
	}
	if err := tdns.RegisterNotifyHandler(0, krsNotifyHandler); err != nil {
		return fmt.Errorf("failed to register KRS NOTIFY handler: %v", err)
	}
	log.Printf("KRS: Registered NOTIFY handler for all NOTIFYs")

	// Register engines using the registration API
	if len(krsConf.DnsEngine.Addresses) > 0 {
		if err := tdns.RegisterEngine("DnsEngine", func(ctx context.Context) error {
			return tdns.DnsEngine(ctx, conf)
		}); err != nil {
			return fmt.Errorf("failed to register DnsEngine: %v", err)
		}
	} else {
		log.Printf("KRS: WARNING: No DNS engine addresses configured, DnsEngine not started")
	}
	log.Printf("KRS: DnsEngine started")

	if err := tdns.RegisterEngine("KeyStateWorker", func(ctx context.Context) error {
		return krs.KeyStateWorker(ctx, krsDB)
	}); err != nil {
		return fmt.Errorf("failed to register KeyStateWorker: %v", err)
	}
	log.Printf("KRS: KeyStateWorker started")

	// Start all registered engines (including DnsEngine and KeyStateWorker)
	tdns.StartRegisteredEngines(ctx)

	log.Printf("TDNS %s (%s): KRS started successfully", tdns.Globals.App.Name, tdns.AppTypeToString[tdns.Globals.App.Type])
	return nil
}
