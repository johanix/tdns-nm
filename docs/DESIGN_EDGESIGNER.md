# Design: tdns-edgesigner - Authoritative DNS Server with KRS Integration

## Overview

`tdns-edgesigner` is a new authoritative DNS server application that combines:
1. **Authoritative DNS Server** functionality (from `tdns-auth`)
2. **Key Receiving Service (KRS)** functionality (from `tdns-krs`)

The server acts as an edge signing node that:
- Serves authoritative DNS responses for configured zones
- Performs online DNSSEC signing using keys from its keystore
- Receives new DNSSEC keys from a KDC via the KRS protocol
- Automatically stores received keys in its keystore for immediate use

## Architecture

### Location
- **Application**: `tdns-nm/cmd/tdns-edgesigner/`
- **Library Code**: `tdns-nm/tnm/edgesigner/` (new package)
- **Shared Code**: Reuses `tdns/v2/tdns` (keystore, DNS engine, etc.)

### Component Integration

```
┌─────────────────────────────────────────────────────────┐
│              tdns-edgesigner Application                │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────┐         ┌──────────────────┐    │
│  │  DNS Engine       │         │  KRS Engine      │    │
│  │  (from tdns-auth) │         │  (from tdns-krs) │    │
│  └────────┬──────────┘         └────────┬─────────┘    │
│           │                              │              │
│           └──────────┬───────────────────┘              │
│                      │                                  │
│              ┌───────▼────────┐                         │
│              │  Unified       │                         │
│              │  Keystore      │                         │
│              │  (tdns KeyDB)  │                         │
│              └────────────────┘                         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Unified Keystore
- **Single SQLite database** containing both:
  - `DnssecKeyStore` table (tdns-auth format) - for online signing
  - `received_keys` table (KRS format) - for tracking key distribution
- **Key Synchronization**: When KRS receives a key, it must be stored in BOTH tables
- **State Mapping**:
  - KRS `edgesigner` state → Keystore `edgesigner` state
  - KRS `active` state → Keystore `active` state (for KSKs)
  - KRS `retired` state → Keystore `retired` state

### 2. Code Reuse Strategy

#### From tdns-auth (via tdns library):
- DNS query handling (`tdns/v2/tdns`)
- Zone management and loading
- Online signing engine
- Keystore (`KeyDB` with `DnssecKeyStore` table)
- Configuration structure (`tdns.Conf`)
- API server for management

#### From tdns-krs:
- KRS protocol handlers (NOTIFY receiver, CHUNK query processing)
- HPKE decryption logic
- Distribution processing (`ProcessDistributionCHUNK`, `ProcessEncryptedKeys`)
- Confirmation sending (`SendConfirmationToKDC`)
- KRS database schema (`received_keys` table)

#### New Code (tdns-nm/tnm/edgesigner):
- Integration layer between KRS and keystore
- Key format conversion (KRS format → Keystore format)
- Unified configuration structure
- Key synchronization logic

## Detailed Design

### 1. Directory Structure

```
tdns-nm/
├── cmd/
│   └── tdns-edgesigner/
│       ├── main.go              # Application entry point
│       ├── version.go           # Version info
│       ├── Makefile
│       ├── go.mod
│       └── tdns-edgesigner.sample.yaml
│
└── tnm/
    └── edgesigner/
            ├── config.go        # Unified configuration
            ├── keystore_bridge.go # KRS → Keystore conversion
            ├── krs_handler.go    # KRS protocol handlers
            ├── integration.go    # Main integration logic
            └── db.go            # Database initialization (unified schema)
```

### 2. Configuration Structure

```yaml
# tdns-edgesigner.sample.yaml

# Inherit all tdns-auth configuration
include:
   - auth-templates.yaml
   - auth-zones.yaml

# tdns-auth configuration
service:
   name: TDNS-EDGESIGNER
   # ... (all standard tdns-auth config)

dnsengine:
   # ... (all standard tdns-auth config)

# KRS-specific configuration
krs:
   enabled: true
   node:
      id: "edgesigner1.example.com."
      long_term_priv_key: /etc/tdns/keys/edgesigner1.priv
   control_zone: "kdc.example.com."
   kdc_address: "192.0.2.1:5353"
   use_chunk: true  # Use CHUNK format (not MANIFEST+OLDCHUNK)
   
# Unified database (both keystore and KRS tables)
db:
   file: /var/lib/tdns-edgesigner/tdns.db  # SQLite database

# API server (for management)
apiserver:
   addresses: [ "127.0.0.1:8991" ]
   # ... (standard API config)
```

### 3. Database Schema

The unified database contains both schemas:

```sql
-- tdns-auth keystore schema
CREATE TABLE IF NOT EXISTS 'DnssecKeyStore' (
   id          INTEGER PRIMARY KEY,
   zonename    TEXT,
   state       TEXT,
   keyid       INTEGER,
   flags       INTEGER,
   algorithm   TEXT,
   creator     TEXT,
   privatekey  TEXT,
   keyrr       TEXT,
   comment     TEXT,
   UNIQUE (zonename, keyid)
);

-- KRS received_keys schema
CREATE TABLE IF NOT EXISTS received_keys (
   id              TEXT PRIMARY KEY,
   zone_name       TEXT NOT NULL,
   key_id          INTEGER NOT NULL,
   key_type        TEXT NOT NULL,
   algorithm       INTEGER NOT NULL,
   flags           INTEGER NOT NULL,
   public_key      TEXT NOT NULL,
   private_key     BLOB NOT NULL,
   state           TEXT NOT NULL DEFAULT 'received',
   received_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
   activated_at    TIMESTAMP NULL,
   retired_at      TIMESTAMP NULL,
   retire_time     TEXT NULL,
   distribution_id TEXT NOT NULL,
   comment         TEXT,
   UNIQUE(zone_name, key_id),
   CHECK (state IN ('received', 'active', 'edgesigner', 'retired', 'removed'))
);
```

### 4. Key Flow: KRS → Keystore

When KRS receives a key distribution:

1. **KRS Processing** (existing `ProcessEncryptedKeys`):
   - Decrypts encrypted keys using HPKE
   - Parses JSON key entries
   - Stores in `received_keys` table with state `edgesigner` (ZSK) or `active` (KSK)

2. **Keystore Bridge** (new `keystore_bridge.go`):
   - Converts KRS `ReceivedKey` format to Keystore `KeystorePost` format
   - Maps key states appropriately
   - Converts private key format (if needed)
   - Calls `KeyDB.DnssecKeyMgmt()` to store in `DnssecKeyStore`

3. **Key Format Conversion**:
   ```go
   // KRS format → Keystore format
   func ConvertKRSKeyToKeystore(key *krs.ReceivedKey) *tdns.KeystorePost {
       return &tdns.KeystorePost{
           SubCommand: "add",
           Zone:       key.ZoneName,
           Keyid:      key.KeyID,
           Flags:      key.Flags,
           Algorithm:  key.Algorithm,
           PrivateKey: string(key.PrivateKey), // Convert BLOB to string
           KeyRR:      key.PublicKey,          // DNSKEY RR string
           State:      mapKRSStateToKeystoreState(key.State),
           Creator:    "krs-distribution",
       }
   }
   ```

### 5. Integration Points

#### A. Application Initialization (`main.go`)

```go
func main() {
    // 1. Initialize tdns configuration (like tdns-auth)
    conf := &tdns.Conf
    err := conf.MainInit(ctx, DefaultEdgesignerCfgFile)
    
    // 2. Initialize unified database
    keyDB, err := edgesigner.InitUnifiedDB(conf.DB.File)
    
    // 3. Set up KRS handlers
    krsConf := edgesigner.LoadKRSConfig(conf)
    krsHandler := edgesigner.NewKRSHandler(keyDB, krsConf)
    
    // 4. Set up DNS query handlers (standard tdns-auth)
    apirouter, err := conf.SetupAPIRouter(ctx)
    
    // 5. Start KRS NOTIFY receiver
    go krsHandler.StartNotifyReceiver(ctx)
    
    // 6. Start DNS engine (standard tdns-auth)
    err = conf.StartAuth(ctx, apirouter)
    
    // 7. Main loop
    conf.MainLoop(ctx, stop)
}
```

#### B. KRS Handler (`krs_handler.go`)

```go
type KRSHandler struct {
    keyDB    *tdns.KeyDB  // Unified keystore
    krsDB    *krs.KrsDB   // KRS tracking database
    config   *KRSConfig
    bridge   *KeystoreBridge
}

func (h *KRSHandler) StartNotifyReceiver(ctx context.Context) {
    // Listen for NOTIFY(CHUNK) messages from KDC
    // Process distributions
    // Store keys in both received_keys and DnssecKeyStore
}

func (h *KRSHandler) HandleDistribution(distributionID string) error {
    // 1. Process distribution (existing KRS logic)
    keys, err := krs.ProcessDistributionCHUNK(h.krsDB, h.config, distributionID)
    
    // 2. For each received key, store in keystore
    for _, key := range keys {
        keystoreKey := h.bridge.ConvertToKeystore(key)
        err := h.keyDB.DnssecKeyMgmt(nil, keystoreKey)
        // Handle errors, track status
    }
    
    // 3. Send confirmation to KDC
    return krs.SendConfirmationToKDC(...)
}
```

#### C. Keystore Bridge (`keystore_bridge.go`)

```go
type KeystoreBridge struct {
    keyDB *tdns.KeyDB
}

func (b *KeystoreBridge) StoreKRSKey(key *krs.ReceivedKey) error {
    // Convert KRS key format to keystore format
    keystoreKey := b.ConvertKRSKeyToKeystore(key)
    
    // Store in DnssecKeyStore
    resp, err := b.keyDB.DnssecKeyMgmt(nil, keystoreKey)
    
    // Update received_keys table to mark as stored
    // (optional: add a flag to track keystore sync status)
    
    return err
}

func (b *KeystoreBridge) ConvertKRSKeyToKeystore(key *krs.ReceivedKey) *tdns.KeystorePost {
    // Format conversion logic
}
```

### 6. State Management

**Key States in received_keys** (KRS tracking):
- `received`: Key received but not yet stored in keystore
- `edgesigner`: ZSK stored in keystore, ready for signing
- `active`: KSK stored in keystore, active
- `retired`: Key retired (no longer used)
- `removed`: Key removed from keystore

**Key States in DnssecKeyStore** (tdns-auth):
- `edgesigner`: ZSK for online signing
- `active`: Active KSK
- `retired`: Retired key
- `standby`: Standby key (not used)

**State Synchronization**:
- When KRS stores a key in `edgesigner` state → Store in keystore with `edgesigner` state
- When KRS stores a key in `active` state → Store in keystore with `active` state
- When a key is retired in keystore → Update `received_keys` to `retired`
- Keystore is the source of truth for signing; `received_keys` is for tracking

### 7. Error Handling

- **Key Storage Failure**: If storing in keystore fails, mark in `received_keys` with error status
- **Format Conversion Failure**: Log error, don't store in keystore, report failure to KDC
- **Duplicate Keys**: Handle gracefully (keystore has UNIQUE constraint on zone+keyid)
- **Key Retirement**: When KRS retires a key, also update keystore state

### 8. API Extensions

Extend the standard tdns-auth API with KRS-specific endpoints:

```go
// GET /api/v1/krs/keys
// List keys received via KRS

// GET /api/v1/krs/distributions
// List key distributions received

// POST /api/v1/krs/process-distribution
// Manually trigger distribution processing
```

### 9. Dependencies

```go
// tdns-nm/cmd/tdns-edgesigner/go.mod
module github.com/johanix/tdns-nm/cmd/tdns-edgesigner

require (
    github.com/johanix/tdns/v2/tdns v0.x.x  // tdns library (keystore, DNS engine)
    github.com/johanix/tdns-nm/tnm/krs v0.x.x // KRS library
    github.com/johanix/tdns-nm/tnm/edgesigner v0.x.x // Integration layer
    // ... other dependencies
)
```

### 10. Migration Path

1. **Phase 1**: Basic integration
   - Create `tdns-edgesigner` application structure
   - Implement unified database schema
   - Port KRS NOTIFY receiver

2. **Phase 2**: Key synchronization
   - Implement keystore bridge
   - Test key conversion and storage
   - Verify keys are usable for signing

3. **Phase 3**: Full integration
   - Complete API extensions
   - Add monitoring and logging
   - Performance testing

4. **Phase 4**: Production readiness
   - Documentation
   - Configuration examples
   - Deployment guides

## Benefits

1. **Single Application**: One server handles both DNS serving and key distribution
2. **Automatic Key Updates**: Keys from KDC automatically available for signing
3. **Unified Management**: Single database, single configuration file
4. **Code Reuse**: Leverages existing, tested code from both tdns-auth and tdns-krs
5. **Simplified Deployment**: Fewer moving parts, easier to manage

## Open Questions

1. **Key Format**: Are private keys from KDC in the same format as tdns-auth expects?
2. **State Synchronization**: Should we add a sync status field to track keystore storage?
3. **Key Retirement**: Who initiates key retirement - KDC or edgesigner?
4. **Performance**: Should key storage be synchronous or asynchronous?
5. **Rollback**: How to handle failed key installations?

## Next Steps

1. Review and refine this design
2. Create initial code structure
3. Implement unified database schema
4. Implement keystore bridge
5. Integrate KRS handlers
6. Test end-to-end key flow

