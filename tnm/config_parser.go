/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Configuration parsing for tdns-kdc and tdns-krs
 */

package tnm

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	tdns "github.com/johanix/tdns/v2"
	"gopkg.in/yaml.v3"
)

// ParseKdcConfigFromFile reads the config file and returns its KDC configuration section.
func ParseKdcConfigFromFile(conf *tdns.Config) (*KdcConf, error) {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return nil, fmt.Errorf("no config file specified")
	}

	// Read the config file
	if tdns.Globals.Debug {
		log.Printf("ParseKdcConfigFromFile: Reading %q", cfgfile)
	}
	data, err := os.ReadFile(cfgfile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file %s: %v", cfgfile, err)
	}

	// Parse YAML into a map
	var configMap map[string]interface{}
	if err := yaml.Unmarshal(data, &configMap); err != nil {
		return nil, fmt.Errorf("error parsing YAML: %v", err)
	}

	// Handle includes if present (similar to tdns processConfigFile)
	configMap, err = processIncludes(configMap, filepath.Dir(cfgfile), 0)
	if err != nil {
		return nil, fmt.Errorf("error processing includes: %v", err)
	}

	// Extract the kdc section
	kdcSection, ok := configMap["kdc"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("KDC configuration section 'kdc' not found or invalid")
	}

	// Round-trip the kdc section through YAML into the typed config
	kdcYAML, err := yaml.Marshal(kdcSection)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KDC config: %v", err)
	}
	var kdcConf KdcConf
	if err := yaml.Unmarshal(kdcYAML, &kdcConf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KDC config: %v", err)
	}

	if tdns.Globals.Debug {
		log.Printf("KDC config section found and parsed")
	}

	return &kdcConf, nil
}

// ParseKrsConfigFromFile reads the config file and returns its KRS configuration section.
// Note: the listeners config is at top level (like KDC), but we merge it into the krs
// section as its dnsengine
func ParseKrsConfigFromFile(conf *tdns.Config) (*KrsConf, error) {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return nil, fmt.Errorf("no config file specified")
	}

	// Read the config file
	if tdns.Globals.Debug {
		log.Printf("ParseKrsConfigFromFile: Reading %q", cfgfile)
	}
	data, err := os.ReadFile(cfgfile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file %s: %v", cfgfile, err)
	}

	// Parse YAML into a map
	var configMap map[string]interface{}
	if err := yaml.Unmarshal(data, &configMap); err != nil {
		return nil, fmt.Errorf("error parsing YAML: %v", err)
	}

	// Handle includes if present (similar to tdns processConfigFile)
	configMap, err = processIncludes(configMap, filepath.Dir(cfgfile), 0)
	if err != nil {
		return nil, fmt.Errorf("error processing includes: %v", err)
	}

	// Extract the krs section
	krsSection, ok := configMap["krs"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("KRS configuration section 'krs' not found or invalid")
	}

	// Extract listeners from top level and merge into krs section as its dnsengine
	if dnsEngineSection, ok := configMap["listeners"].(map[string]interface{}); ok {
		krsSection["dnsengine"] = dnsEngineSection
	}

	// Round-trip the krs section (now including dnsengine) through YAML into the typed config
	krsYAML, err := yaml.Marshal(krsSection)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KRS config: %v", err)
	}
	var krsConf KrsConf
	if err := yaml.Unmarshal(krsYAML, &krsConf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KRS config: %v", err)
	}

	if tdns.Globals.Debug {
		log.Printf("KRS config section found and parsed")
	}

	return &krsConf, nil
}

// processIncludes handles include directives in the config file
func processIncludes(config map[string]interface{}, baseDir string, depth int) (map[string]interface{}, error) {
	if depth > 10 {
		return nil, fmt.Errorf("maximum include depth exceeded (10 levels)")
	}

	// Handle includes if present
	if includes, ok := config["include"].([]interface{}); ok {
		delete(config, "include")
		for _, inc := range includes {
			if includeFile, ok := inc.(string); ok {
				var fullPath string
				if filepath.IsAbs(includeFile) {
					fullPath = includeFile
				} else {
					fullPath = filepath.Join(baseDir, includeFile)
				}
				fullPath = filepath.Clean(fullPath)

				// Read included file
				data, err := os.ReadFile(fullPath)
				if err != nil {
					return nil, fmt.Errorf("error reading included file %s: %v", fullPath, err)
				}

				// Parse included YAML
				var included map[string]interface{}
				if err := yaml.Unmarshal(data, &included); err != nil {
					return nil, fmt.Errorf("error parsing included file %s: %v", fullPath, err)
				}

				// Recursively process includes in the included file
				included, err = processIncludes(included, filepath.Dir(fullPath), depth+1)
				if err != nil {
					return nil, err
				}

				// Merge included config
				for k, v := range included {
					if existing, exists := config[k]; exists {
						// If both are maps, merge them
						if existingMap, ok1 := existing.(map[string]interface{}); ok1 {
							if newMap, ok2 := v.(map[string]interface{}); ok2 {
								for k2, v2 := range newMap {
									existingMap[k2] = v2
								}
								continue
							}
						}
					}
					// Otherwise just override
					config[k] = v
				}
			}
		}
	}

	return config, nil
}
