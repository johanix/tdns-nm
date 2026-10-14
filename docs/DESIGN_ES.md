# TDNS Edge Signer Design Document

## 1. Introduction

### 1.1 Purpose

The TDNS Edge Signer (tdns-es) is a DNS authoritative nameserver with integrated Key Receiving Service (KRS) functionality. It combines the DNS serving capabilities of `tdns-auth` with the key management capabilities of `tdns-krs`, enabling centralized DNSSEC key distribution to edge signing nodes.

### 1.2 Goals

1. **Receive DNSSEC keys from KDC** - Accept HPKE-encrypted key distributions via DNS CHUNK records
2. **Serve DNS zones with online signing** - Sign responses using keys received from KDC
3. **Accept zone assignments from KDC** - Dynamically add/remove zones via component distributions
4. **Maintain compatibility** - Preserve tdns-auth as a standalone product with no breaking changes

### 1.3 Non-Goals

- Recursive resolution (not an IMR)
- Child zone delegation management
- SIG(0) key management (initially)

---

## 2. Architecture Overview

### 2.1 High-Level Architecture

```
                                    ┌─────────────────────────────────────┐
                                    │         tdns-edgesigner             │
                                    │                                     │
    ┌─────────┐                     │  ┌─────────────┐  ┌─────────────┐  │
    │   KDC   │──── NOTIFY ────────▶│  │  KRS Layer  │  │  Auth Layer │  │
    │         │◀─── Confirmation ───│  │             │  │             │  │
    └─────────┘                     │  │ - NOTIFY    │  │ - DNS       │  │
                                    │  │   handler   │  │   engine    │  │
                                    │  │ - CHUNK     │  │ - Resigner  │  │
                                    │  │   fetch     │  │ - Zone      │  │
                                    │  │ - HPKE      │  │   data      │  │
                                    │  │   decrypt   │  │             │  │
                                    │  └──────┬──────┘  └──────▲──────┘  │
    ┌─────────┐                     │         │                │         │
    │  DNS    │                     │         ▼                │         │
    │ Clients │◀─── DNS Queries ────│  ┌─────────────────────────────┐  │
    └─────────┘                     │  │      Combined Database       │  │
                                    │  │  ┌─────────────────────────┐ │  │
                                    │  │  │    received_keys (KRS)  │ │  │
                                    │  │  ├─────────────────────────┤ │  │
                                    │  │  │  dnssec_keystore (Auth) │ │  │
                                    │  │  └─────────────────────────┘ │  │
                                    │  └─────────────────────────────┘  │
                                    └─────────────────────────────────────┘
```

### 2.2 Key Flows

#### Flow 1: Key Distribution

```
1. KDC creates distribution with roll_key operation
2. KDC sends NOTIFY(<dist_id>.<control_zone>) to edge signer
3. Edge signer NotifyRouter recognizes KDC NOTIFY
4. KRS handler queries CHUNK records from KDC
5. KRS decrypts HPKE payload using node's private key
6. Key stored in received_keys table
7. KeySyncEngine converts and copies to dnssec_keystore
8. ResignerEngine triggers zone re-signing
9. Edge signer sends confirmation NOTIFY to KDC
```

#### Flow 2: Zone Assignment

```
1. KDC creates distribution with node_components operation
2. Edge signer receives and processes component list
3. ZoneManager compares with current zones
4. New zones added to tdns.Zones
5. Removed zones deleted from tdns.Zones
6. Zone data fetched (from combiner, XFR, or files)
7. Keys synced for each zone
8. ResignerEngine starts signing
```

#### Flow 3: DNS Query

```
1. Client sends DNS query
2. DnsEngine receives query
3. Query handler looks up zone in tdns.Zones
4. RRsets retrieved from zone data
5. If DNSSEC requested:
   a. GetDnssecKeys() retrieves keys from dnssec_keystore
   b. RRsets signed with ZSK
   c. RRSIG added to response
6. Response sent to client
```

---

## 3. Component Design

### 3.1 Repository Structure

```
tdns-es/
├── cmd/
│   └── tdns-es/
│       ├── main.go           # Application entry point
│       └── defaults.go       # App version, name, default config
├── es/
│   ├── config.go             # EdgeSignerConf struct definition
│   ├── config_parse.go       # Configuration file parsing
│   ├── db.go                 # EdgeSignerDB - combined database
│   ├── db_migrations.go      # Schema migrations
│   ├── key_sync.go           # Key synchronization engine
│   ├── zone_manager.go       # Zone management from KDC
│   ├── notify_router.go      # NOTIFY routing (KDC vs DNS)
│   ├── engines.go            # Engine startup orchestration
│   └── api.go                # REST API endpoints
├── docs/
│   └── DESIGN.md             # This document
├── go.mod
├── go.sum
└── README.md
```

### 3.2 EdgeSignerDB (es/db.go)

The combined database provides access to both KRS and KeyDB functionality through a single SQLite connection.

```go
type EdgeSignerDB struct {
    DB        *sql.DB        // Single database connection
    KrsDB     *krs.KrsDB     // KRS operations (embedded)
    KeyDB     *tdns.KeyDB    // KeyDB operations (embedded)
    SyncMutex sync.Mutex     // Protects key sync operations
}

func NewEdgeSignerDB(dsn string) (*EdgeSignerDB, error)
func (esdb *EdgeSignerDB) InitSchema() error
func (esdb *EdgeSignerDB) Close() error
```

#### Database Tables

**From KRS (received_keys):**
```sql
CREATE TABLE received_keys (
    id TEXT PRIMARY KEY,
    zone_name TEXT NOT NULL,
    key_id INTEGER NOT NULL,
    key_type TEXT NOT NULL,        -- "KSK", "ZSK"
    algorithm INTEGER NOT NULL,
    flags INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    private_key BLOB NOT NULL,     -- Raw key bytes
    state TEXT NOT NULL,           -- received, active, edgesigner, retired, removed
    received_at TIMESTAMP,
    activated_at TIMESTAMP,
    retired_at TIMESTAMP,
    retire_time TEXT,
    distribution_id TEXT NOT NULL,
    UNIQUE(zone_name, key_id)
);
```

**From KeyDB (DnssecKeyStore):**
```sql
CREATE TABLE DnssecKeyStore (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zonename TEXT NOT NULL,
    state TEXT NOT NULL,           -- created, published, active, retired, removed
    keyid INTEGER NOT NULL,
    flags INTEGER NOT NULL,
    algorithm INTEGER NOT NULL,
    creator TEXT,
    privatekey TEXT NOT NULL,      -- PEM format
    keyrr TEXT NOT NULL,           -- DNSKEY RR string
    UNIQUE(zonename, keyid)
);
```

**Additional tables:**
- `node_config` - Node identity and KDC connection info
- `node_components` - Assigned components from KDC
- `Sig0KeyStore` - SIG(0) keys (future use)

### 3.3 KeySyncEngine (es/key_sync.go)

Synchronizes keys from `received_keys` to `dnssec_keystore`, converting formats as needed.

```go
type KeySyncManager struct {
    esDB        *EdgeSignerDB
    resignQ     chan *tdns.ZoneData
    syncTrigger chan KeySyncRequest
}

type KeySyncRequest struct {
    ZoneName  string
    KeyID     uint16
    Operation string  // "add", "retire", "remove"
}

func NewKeySyncManager(esDB *EdgeSignerDB, resignQ chan *tdns.ZoneData) *KeySyncManager
func (ksm *KeySyncManager) KeySyncEngine(ctx context.Context) error
func (ksm *KeySyncManager) SyncKeysForZone(zoneName string) error
func (ksm *KeySyncManager) TriggerSync(req KeySyncRequest)
```

#### State Mapping

| KRS State (received_keys) | KeyDB State (dnssec_keystore) |
|---------------------------|-------------------------------|
| `received`                | `created`                     |
| `edgesigner`              | `active`                      |
| `active`                  | `active`                      |
| `retired`                 | `retired`                     |
| `removed`                 | `removed`                     |

#### Key Format Conversion

KRS stores keys as raw bytes; KeyDB stores as PEM strings with DNSKEY RR.

```go
func convertReceivedKeyToKeystore(rk *krs.ReceivedKey) error {
    // 1. Parse raw private key bytes
    privKey, err := parseRawPrivateKey(rk.PrivateKey, rk.Algorithm)

    // 2. Convert to PEM format
    pemKey, err := tdns.PrivateKeyToPEM(privKey)

    // 3. Build DNSKEY RR string
    dnskeyRR := buildDNSKEYRR(rk.ZoneName, rk.Flags, rk.Algorithm, rk.PublicKey)

    // 4. Determine state
    state := mapKrsStateToKeystoreState(rk.State)

    // 5. Insert/update in dnssec_keystore
    return esDB.KeyDB.AddOrUpdateDnssecKey(...)
}

func parseRawPrivateKey(keyBytes []byte, algorithm uint8) (crypto.PrivateKey, error) {
    switch algorithm {
    case dns.ED25519:
        return ed25519.PrivateKey(keyBytes), nil
    case dns.ECDSAP256SHA256:
        // Parse as ECDSA P-256
    case dns.ECDSAP384SHA384:
        // Parse as ECDSA P-384
    case dns.RSASHA256, dns.RSASHA512:
        // Parse as RSA PKCS#1 or PKCS#8
    }
}

func buildDNSKEYRR(zoneName string, flags uint16, algorithm uint8, pubKey string) string {
    // Construct: "zonename. IN DNSKEY flags 3 algorithm <base64-pubkey>"
    return fmt.Sprintf("%s IN DNSKEY %d 3 %d %s", zoneName, flags, algorithm, pubKey)
}
```

### 3.4 NotifyRouter (es/notify_router.go)

Routes incoming DNS NOTIFY messages to appropriate handlers.

```go
func NotifyHandler(ctx context.Context, conf *tdns.Config, esConf *EdgeSignerConf,
                   esDB *EdgeSignerDB) error {
    for {
        select {
        case <-ctx.Done():
            return nil
        case dnr := <-conf.Internal.DnsNotifyQ:
            if isKdcNotify(&dnr, esConf.KrsConf.ControlZone) {
                // KDC distribution notification
                go handleKdcNotify(ctx, &dnr, esDB, esConf)
            } else {
                // Standard DNS NOTIFY (zone transfer trigger)
                tdns.NotifyResponder(ctx, &dnr, ...)
            }
        }
    }
}

func isKdcNotify(dnr *tdns.DnsNotifyRequest, controlZone string) bool {
    // Check if qname ends with control zone
    // e.g., "abc123.kdc.example.com." is KDC notify
    // e.g., "example.com." is standard DNS notify
    return strings.HasSuffix(dns.CanonicalName(dnr.Qname), dns.CanonicalName(controlZone))
}

func handleKdcNotify(ctx context.Context, dnr *tdns.DnsNotifyRequest,
                     esDB *EdgeSignerDB, esConf *EdgeSignerConf) error {
    // Extract distribution ID from qname
    // Delegate to KRS handler
    return krs.HandleKrsNotify(ctx, dnr, esDB.KrsDB, &esConf.KrsConf)
}
```

### 3.5 ZoneManager (es/zone_manager.go)

Manages zones based on KDC component assignments.

```go
type ZoneManager struct {
    esDB         *EdgeSignerDB
    conf         *tdns.Config
    keySyncMgr   *KeySyncManager
    zoneSourcer  ZoneSourcer
}

type ZoneSourcer interface {
    FetchZoneData(zoneName string) (*tdns.ZoneData, error)
}

func NewZoneManager(esDB *EdgeSignerDB, conf *tdns.Config, ksm *KeySyncManager) *ZoneManager
func (zm *ZoneManager) ZoneManagerEngine(ctx context.Context) error
func (zm *ZoneManager) ProcessComponentUpdate(components []string) error
func (zm *ZoneManager) AddZone(zoneName string) error
func (zm *ZoneManager) RemoveZone(zoneName string) error
```

#### Zone Addition Flow

```go
func (zm *ZoneManager) AddZone(zoneName string) error {
    // 1. Create ZoneData structure
    zd := &tdns.ZoneData{
        ZoneName:  zoneName,
        ZoneStore: tdns.MapZone,
        ZoneType:  tdns.Primary,
        Options:   map[tdns.ZoneOption]bool{
            tdns.OptOnlineSigning: true,
        },
        KeyDB: zm.esDB.KeyDB,
    }

    // 2. Fetch zone data (records)
    zoneData, err := zm.zoneSourcer.FetchZoneData(zoneName)
    if err != nil {
        return fmt.Errorf("failed to fetch zone data: %v", err)
    }
    zd.Data = zoneData.Data

    // 3. Register zone
    tdns.Zones.Set(zoneName, zd)

    // 4. Sync keys for this zone
    zm.keySyncMgr.SyncKeysForZone(zoneName)

    // 5. Trigger re-signing
    zm.conf.Internal.ResignQ <- zd

    return nil
}
```

### 3.6 Configuration (es/config.go)

```go
type EdgeSignerConf struct {
    // Node identity
    Node struct {
        ID             string `yaml:"id"`
        LongTermPubKey string `yaml:"long_term_pub_key"`
        LongTermPrivKey string `yaml:"long_term_priv_key"`
    } `yaml:"node"`

    // KDC connection
    KDC struct {
        Address     string `yaml:"address"`
        ControlZone string `yaml:"control_zone"`
    } `yaml:"kdc"`

    // Database
    Database struct {
        DSN string `yaml:"dsn"`
    } `yaml:"database"`

    // Zone data source
    ZoneSource struct {
        Type    string `yaml:"type"`    // "combiner", "xfr", "file"
        Default string `yaml:"default"` // Default source URL/path
    } `yaml:"zone_source"`

    // Key synchronization
    KeySync struct {
        Interval  string `yaml:"interval"`   // Periodic sync interval
        OnReceive bool   `yaml:"on_receive"` // Sync immediately on key receive
    } `yaml:"key_sync"`

    // Embedded KRS config for compatibility
    KrsConf tnm.KrsConf
}
```

#### Sample Configuration File

```yaml
# tdns-es.yaml

service:
  name: "edge1.example.com"
  debug: false

node:
  id: "edge1.example.com."
  long_term_pub_key: "/etc/tdns-es/edge1.pub"
  long_term_priv_key: "/etc/tdns-es/edge1.key"

kdc:
  address: "kdc.example.com:53"
  control_zone: "kdc.example.com."

database:
  dsn: "/var/lib/tdns-es/edgesigner.db"

zone_source:
  type: "combiner"
  default: "https://combiner.example.com/api/v1"

key_sync:
  interval: "5m"
  on_receive: true

# DNS server configuration (inherited from tdns)
dnsengine:
  addresses:
    - "0.0.0.0:53"
  transports:
    - do53
    - dot

# Re-signing configuration
resignerengine:
  interval: 300
```

### 3.7 Engine Startup (es/engines.go)

```go
func StartEdgeSigner(ctx context.Context, conf *tdns.Config, esConf *EdgeSignerConf,
                     esDB *EdgeSignerDB, apirouter *mux.Router) error {

    // Communication channels
    resignQ := make(chan *tdns.ZoneData, 100)
    conf.Internal.ResignQ = resignQ

    // Create managers
    keySyncMgr := NewKeySyncManager(esDB, resignQ)
    zoneMgr := NewZoneManager(esDB, conf, keySyncMgr)

    // --- TDNS Core Engines ---

    // API server
    startEngine("APIdispatcher", func() error {
        return tdns.APIdispatcher(conf, apirouter, conf.Internal.APIStopCh)
    })

    // DNS server
    startEngine("DnsEngine", func() error {
        return tdns.DnsEngine(ctx, conf)
    })

    // Re-signing engine
    startEngineNoError("ResignerEngine", func() {
        tdns.ResignerEngine(ctx, resignQ)
    })

    // Zone data updates
    startEngine("ZoneUpdaterEngine", func() error {
        return esDB.KeyDB.ZoneUpdaterEngine(ctx)
    })

    // --- KRS Engines ---

    // Key state transitions (retired -> removed)
    startEngine("KeyStateWorker", func() error {
        return krs.KeyStateWorker(ctx, esDB.KrsDB)
    })

    // --- Edge Signer Engines ---

    // Custom NOTIFY routing
    startEngine("NotifyHandler", func() error {
        return NotifyHandler(ctx, conf, esConf, esDB)
    })

    // Key synchronization
    startEngine("KeySyncEngine", func() error {
        return keySyncMgr.KeySyncEngine(ctx)
    })

    // Zone management
    startEngine("ZoneManagerEngine", func() error {
        return zoneMgr.ZoneManagerEngine(ctx)
    })

    return nil
}
```

### 3.8 Main Entry Point (cmd/tdns-es/main.go)

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    tdns "github.com/johanix/tdns/tdns"
    "github.com/johanix/tdns-es/es"
)

func main() {
    // Set application type
    tdns.Globals.App.Name = AppName
    tdns.Globals.App.Version = AppVersion
    tdns.Globals.App.Type = tdns.AppTypeEdgeSigner

    // Context with signal handling
    ctx, stop := signal.NotifyContext(context.Background(),
        syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    // Initialize TDNS base
    conf := &tdns.Conf
    if err := conf.MainInit(ctx, DefaultCfgFile); err != nil {
        log.Fatalf("MainInit failed: %v", err)
    }

    // Parse edge signer configuration
    esConf, err := es.ParseConfig(conf.Internal.CfgFile)
    if err != nil {
        log.Fatalf("Failed to parse edge signer config: %v", err)
    }

    // Initialize combined database
    esDB, err := es.NewEdgeSignerDB(esConf.Database.DSN)
    if err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }
    defer esDB.Close()

    // Setup API router
    apirouter, err := conf.SetupAPIRouter(ctx)
    if err != nil {
        log.Fatalf("Failed to setup API router: %v", err)
    }

    // Add edge signer API routes
    es.SetupAPIRoutes(apirouter, esDB, esConf)

    // Start edge signer engines
    if err := es.StartEdgeSigner(ctx, conf, esConf, esDB, apirouter); err != nil {
        log.Fatalf("Failed to start edge signer: %v", err)
    }

    log.Printf("TDNS Edge Signer started: %s", esConf.Node.ID)

    // Main loop
    conf.MainLoop(ctx, stop)
}
```

---

## 4. Required Changes to Existing Repos

### 4.1 Changes to tdns (REQUIRES APPROVAL)

**File:** `v0.x/enums.go`

Add new AppType constant:
```go
const (
    AppTypeAuth AppType = iota + 1
    AppTypeAgent
    AppTypeCombiner
    AppTypeImr
    AppTypeCli
    AppTypeReporter
    AppTypeScanner
    AppTypeKdc
    AppTypeKrs
    AppTypeEdgeSigner  // NEW: Edge Signer (auth + KRS)
)

var AppTypeToString = map[AppType]string{
    // ... existing ...
    AppTypeEdgeSigner: "edgesigner",  // NEW
}

var StringToAppType = map[string]AppType{
    // ... existing ...
    "edgesigner": AppTypeEdgeSigner,  // NEW
}
```

**File:** `tdns/main_initfuncs.go`

Add AppTypeEdgeSigner to the switch statements in MainInit():
```go
case AppTypeAuth, AppTypeAgent, AppTypeCombiner, AppTypeScanner, AppTypeReporter, AppTypeEdgeSigner:
    // ... existing code ...
```

### 4.2 Changes to tdns-nm (NO APPROVAL REQUIRED)

**Potential changes:**
- Export any currently unexported functions needed by edge signer
- Ensure KrsDB can be embedded in EdgeSignerDB
- Add helper functions for key format conversion if needed

---

## 5. Implementation Phases

### Phase 1: Foundation (Estimated: 2-3 days)
1. Add `AppTypeEdgeSigner` to tdns (requires approval)
2. Create `go.mod` with local replace directives
3. Implement `EdgeSignerDB` with combined schema
4. Implement `main.go` with basic startup
5. Implement `config.go` and `config_parse.go`

### Phase 2: NOTIFY Routing (Estimated: 1-2 days)
1. Implement `notify_router.go`
2. Integrate KRS NOTIFY handler
3. Test KDC distribution flow end-to-end

### Phase 3: Key Synchronization (Estimated: 2-3 days)
1. Implement key format conversion functions
2. Implement `KeySyncEngine`
3. Test key sync with manual key insertion
4. Test automatic sync on key receive

### Phase 4: Zone Management (Estimated: 2-3 days)
1. Implement `ZoneManager`
2. Implement zone sourcing (combiner integration)
3. Test zone addition from component assignment
4. Test zone removal

### Phase 5: Integration Testing (Estimated: 1-2 days)
1. End-to-end test with KDC and edge signer
2. Key rollover test
3. Zone management test
4. DNS query and signing test

---

## 6. Testing Plan

### 6.1 Unit Tests

- `db_test.go` - Database operations, schema creation
- `key_sync_test.go` - Key format conversion, state mapping
- `notify_router_test.go` - NOTIFY classification
- `zone_manager_test.go` - Zone add/remove operations

### 6.2 Integration Tests

**Test 1: Basic Startup**
```bash
./tdns-es --config tdns-es.yaml
# Verify: DNS server listening, API responding
dig @localhost SOA . +short  # Should get response
curl http://localhost:8080/api/v1/status  # Should return OK
```

**Test 2: Key Distribution**
```bash
# On KDC:
kdc-cli zone dnssec distribute --zone test.example. --keyid 12345 --nodeid edge1

# On edge signer, verify:
# 1. Key appears in received_keys
sqlite3 edgesigner.db "SELECT * FROM received_keys WHERE zone_name='test.example.'"

# 2. Key synced to dnssec_keystore
sqlite3 edgesigner.db "SELECT * FROM DnssecKeyStore WHERE zonename='test.example.'"

# 3. Confirmation sent to KDC (check KDC logs)
```

**Test 3: DNS Signing**
```bash
# Query with DNSSEC
dig @edgesigner test.example. SOA +dnssec

# Verify RRSIG present and validates
dig @edgesigner test.example. SOA +dnssec +cd  # CD flag to skip validation
# Compare: with validation, without CD flag
```

**Test 4: Zone Management**
```bash
# On KDC: assign zone to edge signer
kdc-cli node components update --nodeid edge1 --add zone:new.example.

# On edge signer, verify:
# 1. Zone appears in served zones
dig @edgesigner new.example. SOA

# 2. Component recorded
sqlite3 edgesigner.db "SELECT * FROM node_components"
```

---

## 7. Security Considerations

### 7.1 Key Protection

- Private keys stored encrypted in database (HPKE decryption on receive)
- Database file should have restricted permissions (0600)
- Long-term HPKE private key file should be protected

### 7.2 NOTIFY Authentication

- KDC NOTIFYs should be authenticated (SIG(0) or IP-based)
- Standard DNS NOTIFYs should follow RFC-compliant validation
- Consider adding source IP filtering for KDC

### 7.3 API Security

- API should require authentication (API key or mTLS)
- Key material should not be exposed via API (only metadata)
- Rate limiting on API endpoints

---

## 8. Future Enhancements

1. **SIG(0) Key Management** - Add support for SIG(0) keys for secure DNS updates
2. **Key Usage Metrics** - Track signing operations per key
3. **Multi-KDC Support** - Accept keys from multiple KDCs
4. **Hot Standby** - Synchronize state between primary/backup edge signers
5. **TSIG Support** - Add TSIG authentication for zone transfers
