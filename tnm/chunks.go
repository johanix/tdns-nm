/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Shared chunk splitting and reassembly functions
 * DEPRECATED: Use github.com/johanix/tdns/v2/distrib instead
 */

package tnm

import (
	"github.com/johanix/tdns-transport/v2/distrib"
	"github.com/johanix/tdns/v2/core"
)

// SplitIntoCHUNKs splits data into CHUNK records of specified size
// DEPRECATED: Use distrib.SplitIntoCHUNKs instead
func SplitIntoCHUNKs(data []byte, chunkSize int, format uint8) []*core.CHUNK {
	return distrib.SplitIntoCHUNKs(data, chunkSize, format)
}

// ReassembleCHUNKChunks reassembles CHUNK chunks into complete data
// DEPRECATED: Use distrib.ReassembleCHUNKs instead
func ReassembleCHUNKChunks(chunks []*core.CHUNK) ([]byte, error) {
	return distrib.ReassembleCHUNKs(chunks)
}
