/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * NOTIFY sending functionality for KDC
 */

package kdc

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// SendNotifyWithDistributionID sends NOTIFY messages to all active nodes for a distribution event
// distributionID is the distribution identifier (e.g., "a1b2")
// controlZone is the control zone name (e.g., "kdc.example.com.")
// The NOTIFY QNAME will be <distributionID>.<controlzone> (e.g., "a1b2.kdc.example.com.")
func (kdc *KdcDB) SendNotifyWithDistributionID(distributionID, controlZone string) error {
	// Get all active nodes
	nodes, err := kdc.GetActiveNodes()
	if err != nil {
		return fmt.Errorf("failed to get active nodes: %v", err)
	}

	if len(nodes) == 0 {
		log.Printf("KDC: No active nodes found, skipping NOTIFY")
		return nil
	}

	// Filter nodes that have notify addresses configured
	var targets []string
	for _, node := range nodes {
		if node.NotifyAddress != "" {
			targets = append(targets, node.NotifyAddress)
			log.Printf("KDC: Will send NOTIFY for distribution %s to node %s at %s", distributionID, node.ID, node.NotifyAddress)
		} else {
			log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
		}
	}

	if len(targets) == 0 {
		log.Printf("KDC: No nodes with notify_address configured, skipping NOTIFY")
		return nil
	}

	// Construct NOTIFY QNAME: <distributionID>.<controlzone>
	notifyQname := core.BuildNotifyQNAME(distributionID, controlZone)

	// Send NOTIFY for CHUNK query type
	notifyType := uint16(core.TypeCHUNK) // Use CHUNK RRtype (65015)

	successCount := 0
	for _, dst := range targets {
		typeStr := dns.TypeToString[notifyType]
		if typeStr == "" {
			typeStr = fmt.Sprintf("CHUNK(%d)", notifyType)
		}
		log.Printf("KDC: Sending NOTIFY(%s) for distribution %s (QNAME: %s) to %s", typeStr, distributionID, notifyQname, dst)

		m := new(dns.Msg)
		m.SetNotify(notifyQname)
		m.Question = []dns.Question{
			{Name: notifyQname, Qtype: notifyType, Qclass: dns.ClassINET},
		}

		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Printf("KDC: Error sending NOTIFY to %s: %v", dst, err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			log.Printf("KDC: NOTIFY to %s returned rcode %s", dst, dns.RcodeToString[res.Rcode])
		} else {
			log.Printf("KDC: NOTIFY to %s succeeded", dst)
			successCount++
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send NOTIFY to any node")
	}

	log.Printf("KDC: Successfully sent NOTIFY to %d/%d nodes", successCount, len(targets))
	return nil
}
