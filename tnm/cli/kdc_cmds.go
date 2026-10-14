/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CLI commands for tdns-kdc management
 *
 * This file has been refactored - commands are now organized in separate files:
 *   - kdc_common.go: Shared variables, helper functions, and main init() registration
 *   - kdc_zone_cmds.go: Zone, zone dnssec, zone catalog commands
 *   - kdc_node_cmds.go: Node, node component, node enroll commands
 *   - kdc_distrib_cmds.go: Distribution commands
 *   - kdc_service_cmds.go: Service, service component, service transaction commands
 *   - kdc_component_cmds.go: Component commands
 *   - kdc_config_cmds.go: Config commands
 *   - kdc_debug_cmds.go: Debug commands
 */
package cli
