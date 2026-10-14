/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Confirmation sending functionality for KRS
 */

package krs

import (
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// SendConfirmationToKDC sends a NOTIFY(CHUNK) back to KDC to confirm receipt of keys
// distributionID: The distribution ID that was received
// controlZone: The control zone name (e.g., "kdc.example.com.")
// kdcAddress: The KDC server address (IP:port)
// successfulKeys: List of keys that were successfully installed
// failedKeys: List of keys that failed to install
func SendConfirmationToKDC(distributionID, controlZone, kdcAddress string, successfulKeys, failedKeys []edns0.KeyStatusEntry) error {
	// Construct NOTIFY QNAME: <distributionID>.<controlzone>
	notifyQname := core.BuildNotifyQNAME(distributionID, controlZone)

	// Send NOTIFY for CHUNK query type
	notifyType := uint16(core.TypeCHUNK) // Use CHUNK RRtype (65015)

	typeStr := dns.TypeToString[notifyType]
	if typeStr == "" {
		typeStr = fmt.Sprintf("CHUNK(%d)", notifyType)
	}
	log.Printf("KRS: Sending confirmation NOTIFY(%s) for distribution %s (QNAME: %s) to %s", typeStr, distributionID, notifyQname, kdcAddress)

	m := new(dns.Msg)
	m.SetNotify(notifyQname)
	m.Question = []dns.Question{
		{Name: notifyQname, Qtype: notifyType, Qclass: dns.ClassINET},
	}

	// Add CHUNK EDNS(0) option with key status report if we have status information
	if len(successfulKeys) > 0 || len(failedKeys) > 0 {
		chunkOpt, err := edns0.CreateKeyStatusChunkOption(successfulKeys, failedKeys)
		if err != nil {
			log.Printf("KRS: Warning: Failed to create CHUNK EDNS option: %v", err)
		} else {
			if err := edns0.AddChunkOptionToMessage(m, chunkOpt); err != nil {
				log.Printf("KRS: Warning: Failed to add CHUNK EDNS option to message: %v", err)
			} else {
				log.Printf("KRS: Added CHUNK EDNS option with %d successful and %d failed keys", len(successfulKeys), len(failedKeys))
			}
		}
	}

	// Create a DNS client with a reasonable timeout for NOTIFY
	client := &dns.Client{
		Timeout: 5 * time.Second, // 5 second timeout for NOTIFY
		Net:     "udp",
	}

	res, _, err := client.Exchange(m, kdcAddress)
	if err != nil {
		log.Printf("KRS: Error sending confirmation NOTIFY to %s: %v", kdcAddress, err)
		return fmt.Errorf("failed to send confirmation NOTIFY to %s: %v", kdcAddress, err)
	}

	if res == nil {
		log.Printf("KRS: Confirmation NOTIFY to %s returned nil response", kdcAddress)
		return fmt.Errorf("confirmation NOTIFY returned nil response")
	}

	if res.Rcode != dns.RcodeSuccess {
		log.Printf("KRS: Confirmation NOTIFY to %s returned rcode %s", kdcAddress, dns.RcodeToString[res.Rcode])
		return fmt.Errorf("confirmation NOTIFY returned rcode %s", dns.RcodeToString[res.Rcode])
	}

	log.Printf("KRS: Confirmation NOTIFY to %s succeeded", kdcAddress)
	return nil
}

// SendComponentConfirmationToKDC sends a NOTIFY(CHUNK) back to KDC to confirm receipt of components
// distributionID: The distribution ID that was received
// controlZone: The control zone name (e.g., "kdc.example.com.")
// kdcAddress: The KDC server address (IP:port)
// successfulComponents: List of components that were successfully installed
// failedComponents: List of components that failed to install
func SendComponentConfirmationToKDC(distributionID, controlZone, kdcAddress string, successfulComponents, failedComponents []edns0.ComponentStatusEntry) error {
	// Construct NOTIFY QNAME: <distributionID>.<controlzone>
	notifyQname := core.BuildNotifyQNAME(distributionID, controlZone)

	// Send NOTIFY for CHUNK query type
	notifyType := uint16(core.TypeCHUNK) // Use CHUNK RRtype (65015)

	typeStr := dns.TypeToString[notifyType]
	if typeStr == "" {
		typeStr = fmt.Sprintf("CHUNK(%d)", notifyType)
	}
	log.Printf("KRS: Sending component confirmation NOTIFY(%s) for distribution %s (QNAME: %s) to %s", typeStr, distributionID, notifyQname, kdcAddress)

	m := new(dns.Msg)
	m.SetNotify(notifyQname)
	m.Question = []dns.Question{
		{Name: notifyQname, Qtype: notifyType, Qclass: dns.ClassINET},
	}

	// Add CHUNK EDNS(0) option with component status report if we have status information
	if len(successfulComponents) > 0 || len(failedComponents) > 0 {
		chunkOpt, err := edns0.CreateComponentStatusChunkOption(successfulComponents, failedComponents)
		if err != nil {
			log.Printf("KRS: Warning: Failed to create component status CHUNK EDNS option: %v", err)
		} else {
			if err := edns0.AddChunkOptionToMessage(m, chunkOpt); err != nil {
				log.Printf("KRS: Warning: Failed to add CHUNK EDNS option to message: %v", err)
			} else {
				log.Printf("KRS: Added CHUNK EDNS option with %d successful and %d failed components", len(successfulComponents), len(failedComponents))
			}
		}
	}

	// Create a DNS client with a reasonable timeout for NOTIFY
	client := &dns.Client{
		Timeout: 5 * time.Second, // 5 second timeout for NOTIFY
		Net:     "udp",
	}

	res, _, err := client.Exchange(m, kdcAddress)
	if err != nil {
		log.Printf("KRS: Error sending component confirmation NOTIFY to %s: %v", kdcAddress, err)
		return fmt.Errorf("failed to send component confirmation NOTIFY to %s: %v", kdcAddress, err)
	}

	if res == nil {
		log.Printf("KRS: Component confirmation NOTIFY to %s returned nil response", kdcAddress)
		return fmt.Errorf("component confirmation NOTIFY returned nil response")
	}

	if res.Rcode != dns.RcodeSuccess {
		log.Printf("KRS: Component confirmation NOTIFY to %s returned rcode %s", kdcAddress, dns.RcodeToString[res.Rcode])
		return fmt.Errorf("component confirmation NOTIFY returned rcode %s", dns.RcodeToString[res.Rcode])
	}

	log.Printf("KRS: Component confirmation NOTIFY to %s succeeded", kdcAddress)
	return nil
}
