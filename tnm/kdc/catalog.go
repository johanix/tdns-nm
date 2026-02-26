/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KDC-specific catalog zone generation using RFC 9432 compliant tdns/v2 implementation
 * This file contains KDC-specific wrappers that use shared utilities from tnm/catalog.go
 */

package kdc

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	tnm "github.com/johanix/tdns-nm/tnm"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// GenerateCatalogZone generates an RFC 9432 compliant catalog zone from KDC data
// This is the main entry point for catalog zone generation
// catalogZoneName: The name of the catalog zone (e.g., "catalog.example.com.")
// dnsEngineAddresses: List of addresses (IP:port) that DnsEngine listens on (currently unused, kept for API compatibility)
// Returns: The ZoneData structure for the catalog zone, error
func (kdc *KdcDB) GenerateCatalogZone(catalogZoneName string, dnsEngineAddresses []string) (*tdns.ZoneData, error) {
	if catalogZoneName == "" {
		return nil, fmt.Errorf("catalog zone name is required")
	}

	// Ensure zone name is FQDN
	if !dns.IsFqdn(catalogZoneName) {
		catalogZoneName = dns.Fqdn(catalogZoneName)
	}

	log.Printf("CATALOG: GenerateCatalogZone: Starting generation for catalog zone %s", catalogZoneName)

	// Get all zones from KDC database
	zones, err := kdc.GetAllZones()
	if err != nil {
		return nil, fmt.Errorf("failed to get zones from KDC database: %v", err)
	}

	// Filter to only active zones
	activeZones := make([]*Zone, 0)
	for _, zone := range zones {
		if zone.Active {
			activeZones = append(activeZones, zone)
		}
	}

	log.Printf("CATALOG: GenerateCatalogZone: Found %d active zones (out of %d total)", len(activeZones), len(zones))

	// Check if catalog zone already exists
	zd, exists := tdns.Zones.Get(catalogZoneName)
	if !exists {
		// Create the catalog zone using tdns.CreateAutoZone
		// Use empty addrs to get "invalid." NS record (RFC 9432 recommendation for autozones)
		kdb := &tdns.KeyDB{} // Empty KeyDB for catalog zones
		zd, err = kdb.CreateAutoZone(catalogZoneName, []string{}, []string{})
		if err != nil {
			return nil, fmt.Errorf("failed to create catalog zone: %v", err)
		}

		// Mark it as a catalog zone
		zd.Options[tdns.OptCatalogZone] = true

		// Add version TXT record: version.{catalog} IN TXT "2" (RFC 9432 requirement)
		// Use shared utility from tnm/catalog.go
		err = tnm.AddVersionRecord(zd, catalogZoneName)
		if err != nil {
			return nil, fmt.Errorf("failed to add version record: %v", err)
		}

		// Register with tdns.Zones
		tdns.Zones.Set(catalogZoneName, zd)
		log.Printf("CATALOG: GenerateCatalogZone: Created new catalog zone %s", catalogZoneName)
	} else {
		log.Printf("CATALOG: GenerateCatalogZone: Catalog zone %s already exists, regenerating content", catalogZoneName)
	}

	// Remove all existing zone records (if regenerating)
	// This follows the pattern from tdns/v2/apihandler_catalog.go:regenerateCatalogZone()
	zoneSuffix := fmt.Sprintf(".zones.%s", catalogZoneName)
	removedCount := 0
	for owner := range zd.Data.IterBuffered() {
		if strings.HasSuffix(owner.Key, zoneSuffix) {
			zd.Data.Remove(owner.Key)
			removedCount++
		}
	}
	if removedCount > 0 {
		log.Printf("CATALOG: GenerateCatalogZone: Removed %d existing zone records", removedCount)
	}

	// Collect zone-to-components mapping
	// Component IDs map 1:1 to group names (translation happens at API boundary)
	zoneGroups := make(map[string][]string) // zone identifier (hash) -> list of component IDs (which are group names)

	// First pass: collect all zones and their components
	for _, zone := range activeZones {
		// Generate unique identifier for this zone using shared utility from tnm/catalog.go
		hash := tnm.GenerateZoneHash(zone.Name)

		// Get components for this zone's service
		var components []string
		if zone.ServiceID != "" {
			components, err = kdc.GetComponentsForService(zone.ServiceID)
			if err != nil {
				log.Printf("CATALOG: GenerateCatalogZone: Warning: Failed to get components for service %s (zone %s): %v",
					zone.ServiceID, zone.Name, err)
				// Continue with empty components list
				components = []string{}
			}
		}

		// GetComponentsForService already filters by active=1, but sort for consistent output
		sort.Strings(components)

		// Store groups (component IDs) for this zone
		zoneGroups[hash] = components
		log.Printf("CATALOG: GenerateCatalogZone: Zone %s (hash: %s) has %d components: %v",
			zone.Name, hash, len(components), components)
	}

	// Second pass: generate PTR records for zones
	// Format: {opaque id}.zones.{catalog zone}. IN PTR {zone name}
	for _, zone := range activeZones {
		hash := tnm.GenerateZoneHash(zone.Name)
		ownerName := fmt.Sprintf("%s.zones.%s", hash, catalogZoneName)

		// Create PTR record
		ptrStr := fmt.Sprintf("%s 0 IN PTR %s", ownerName, zone.Name)
		ptr, err := dns.NewRR(ptrStr)
		if err != nil {
			log.Printf("CATALOG: GenerateCatalogZone: Error creating PTR for zone %s: %v", zone.Name, err)
			continue
		}

		// Create RRset for PTR record
		ptrRRset := core.RRset{
			Name:   ownerName,
			RRtype: dns.TypePTR,
			Class:  dns.ClassINET,
			RRs:    []dns.RR{ptr},
		}

		// Get or create OwnerData for this owner
		ownerData, exists := zd.Data.Get(ownerName)
		if !exists {
			ownerData = tdns.OwnerData{
				Name:    ownerName,
				RRtypes: tdns.NewRRTypeStore(),
			}
		}

		// Add the PTR RRset to the owner
		ownerData.RRtypes.Set(dns.TypePTR, ptrRRset)
		zd.Data.Set(ownerName, ownerData)
	}

	// Third pass: generate TXT records for group associations
	// Format: group.{uniqueid}.zones.{catalog} IN TXT "group1" "group2" ... (RFC 9432)
	for _, zone := range activeZones {
		hash := tnm.GenerateZoneHash(zone.Name)
		components := zoneGroups[hash]

		if len(components) > 0 {
			groupOwnerName := fmt.Sprintf("group.%s.zones.%s", hash, catalogZoneName)

			// Create TXT record with all groups (component IDs) as strings
			// Format: "group1" "group2" "group3" ... (all in single TXT RR)
			txtStrings := make([]string, len(components))
			copy(txtStrings, components)

			// Create TXT RR with all group strings
			txtRR := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   groupOwnerName,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: txtStrings,
			}

			// Create RRset for TXT record
			txtRRset := core.RRset{
				Name:   groupOwnerName,
				RRtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				RRs:    []dns.RR{txtRR},
			}

			// Get or create OwnerData for group owner
			groupOwnerData, exists := zd.Data.Get(groupOwnerName)
			if !exists {
				groupOwnerData = tdns.OwnerData{
					Name:    groupOwnerName,
					RRtypes: tdns.NewRRTypeStore(),
				}
			}

			// Add the TXT RRset to the group owner
			groupOwnerData.RRtypes.Set(dns.TypeTXT, txtRRset)
			zd.Data.Set(groupOwnerName, groupOwnerData)
		}
	}

	// Bump SOA serial
	newSerial, err := zd.BumpSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to bump SOA serial: %v", err)
	}

	log.Printf("CATALOG: GenerateCatalogZone: Successfully generated catalog zone %s with %d member zones (serial: %d)",
		catalogZoneName, len(activeZones), newSerial.NewSerial)

	return zd, nil
}

// InitializeCatalogZone checks if catalog zone is configured and generates it on startup
// This should be called from startKdc() after database initialization but before engine start
func InitializeCatalogZone(
	ctx context.Context,
	kdcDB *KdcDB,
	kdcConf *tnm.KdcConf,
) error {
	if kdcConf.CatalogZone == "" {
		log.Printf("CATALOG: InitializeCatalogZone: No catalog zone configured, skipping initialization")
		return nil
	}

	catalogZoneName := kdcConf.CatalogZone
	if !dns.IsFqdn(catalogZoneName) {
		catalogZoneName = dns.Fqdn(catalogZoneName)
	}

	log.Printf("CATALOG: InitializeCatalogZone: Initializing catalog zone %s", catalogZoneName)

	// Check if zone exists in tdns.Zones
	_, exists := tdns.Zones.Get(catalogZoneName)
	if !exists {
		log.Printf("CATALOG: InitializeCatalogZone: Catalog zone %s does not exist, creating and generating", catalogZoneName)
	} else {
		log.Printf("CATALOG: InitializeCatalogZone: Catalog zone %s already exists, regenerating", catalogZoneName)
	}

	// Get DnsEngine addresses from tdns.Conf (for API compatibility, though not used for NS records)
	dnsEngineAddresses := tdns.Conf.DnsEngine.Addresses

	// Generate catalog zone
	zd, err := kdcDB.GenerateCatalogZone(catalogZoneName, dnsEngineAddresses)
	if err != nil {
		// Set error state on catalog zone if it exists
		if zd != nil {
			zd.SetError(tdns.ConfigError, "Failed to initialize catalog zone: %v", err)
		}
		return fmt.Errorf("failed to initialize catalog zone %s: %v", catalogZoneName, err)
	}

	// Clear any previous error state
	zd.SetError(tdns.NoError, "")

	log.Printf("CATALOG: InitializeCatalogZone: Successfully initialized catalog zone %s (serial: %d)",
		catalogZoneName, zd.CurrentSerial)

	return nil
}
