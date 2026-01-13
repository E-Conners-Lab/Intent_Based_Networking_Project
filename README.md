# IBN Platform

**Intent-Based Networking with Z3 Constraint Solving**

An Intent-Based Networking (IBN) platform that translates high-level business requirements into optimal network configurations. Instead of manually calculating paths and writing configs, you declare *what* you want and the platform figures out *how* to achieve it.

## The Problem

Traditional network automation still requires you to think like a router:
- Manually calculate primary and backup paths
- Write hundreds of lines of BGP/OSPF configuration
- Hope your "redundant" paths don't share a common failure point
- Repeat for every change

## The Solution

Define your intent in 6 lines:

```yaml
name: NYC Branch Connectivity
type: branch-wan
source: IBN-HQ
destination: IBN-Branch
requirements:
  latency_ms: 50
  diverse_paths: true
```

The platform:
1. **Solves** - Z3 SMT solver finds mathematically optimal paths with true diversity
2. **Generates** - Produces complete BGP, BFD, and route-map configurations
3. **Deploys** - Pushes configs to devices via SSH
4. **Verifies** - Confirms BGP/BFD sessions are established

## Why Z3?

Standard shortest-path algorithms (Dijkstra, Bellman-Ford) can't express constraints like "find two paths that don't share any failure domain." Z3 can solve this as a constraint satisfaction problem with provable optimality.

```
Constraint: paths must use different failure domains
Constraint: both paths must meet 50ms latency SLA
Objective: minimize total cost

Solution found in 8ms:
  Primary: HQ → Core2 → Branch (Domain B, 33ms)
  Backup:  HQ → Core1 → Branch (Domain A, 22ms)
```

## Features

| Feature | Description |
|---------|-------------|
| **Z3 Constraint Solver** | Finds optimal diverse paths that standard algorithms can't |
| **Failure Domain Awareness** | Ensures backup paths don't share failure points with primary |
| **What-If Analysis** | Simulate node/domain failures before they happen |
| **Config Generation** | Jinja2 templates produce IOS-XE BGP configurations |
| **Live Deployment** | Push configs via SSH with Netmiko |
| **Config Diff** | Preview exactly what will change before deploying |
| **Topology Visualization** | ASCII diagrams showing network and computed paths |
| **Real-Time Monitoring** | Watch BGP/BFD status with live updates |
| **Verification** | Confirm BGP neighbors and BFD sessions are up |
| **Deployment History** | Track all deployments with timestamps and config snapshots |
| **Rollback** | Restore previous configurations with one command |
| **Compliance Monitoring** | Continuous verification that network matches intent |
| **NETCONF/RESTCONF** | Modern API-based device connectivity (YANG models) |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/E-Conners-Lab/Intent_Based_Networking_Project.git
cd Intent_Based_Networking_Project

# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

### Commands

```bash
# Show network topology diagram
ibn show-topology

# Load and validate topology
ibn load-topology examples/lab.yaml

# Validate an intent
ibn validate-intent examples/intents/nyc-branch.yaml

# Solve for optimal paths (shows diagram with paths)
ibn solve examples/intents/nyc-branch.yaml

# Simulate failures
ibn what-if examples/intents/nyc-branch.yaml --fail-node IBN-Core1

# Generate configs (view only)
ibn generate-config examples/intents/nyc-branch.yaml

# Deploy with diff preview
ibn deploy examples/intents/nyc-branch.yaml --diff -u admin -p <password>

# Deploy to devices
ibn deploy examples/intents/nyc-branch.yaml -u admin -p <password>

# Verify BGP/BFD status
ibn verify -u admin -p <password> --bgp --bfd

# Watch network status in real-time
ibn watch -u admin -p <password>

# View deployment history
ibn history

# Rollback to previous configuration
ibn rollback -u admin -p <password>

# Check compliance (one-time)
ibn compliance examples/intents/nyc-branch.yaml -u admin -p <password>

# Continuous compliance monitoring
ibn compliance examples/intents/nyc-branch.yaml -c -i 30 -u admin -p <password>

# Verify via NETCONF (port 830)
ibn verify --protocol netconf -u admin -p <password> --bgp

# Verify via RESTCONF (port 443)
ibn verify --protocol restconf -u admin -p <password> --bgp
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                            │
│  ibn solve | ibn deploy | ibn verify | ibn what-if         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     Intent Parser                           │
│  YAML → Pydantic Models → Validation                        │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Z3 Constraint Solver                     │
│  Flow constraints + Latency + Diversity + Cost optimization │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Config Generator                          │
│  Service Models + Jinja2 Templates → Device Configs         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Device Connector                          │
│  Netmiko SSH → Deploy → Verify                              │
└─────────────────────────────────────────────────────────────┘
```

## Lab Topology

The platform was developed and tested on an EVE-NG lab with Cisco C8000V routers:

```
                    ┌──────────────┐
                    │    IBN-HQ    │
                    │  10.100.0.1  │
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
       ┌──────┴──────┐          ┌──────┴──────┐
       │  IBN-Core1  │          │  IBN-Core2  │
       │  Domain A   │          │  Domain B   │
       │  10.100.0.2 │          │  10.100.0.3 │
       └──────┬──────┘          └──────┬──────┘
              │                         │
              └────────────┬────────────┘
                           │
                    ┌──────┴───────┐
                    │  IBN-Branch  │
                    │  10.100.0.4  │
                    └──────────────┘
```

**Key Design Points:**
- Two failure domains (A and B) for path diversity
- iBGP with local-preference for path selection (primary=200, backup=100)
- BFD for sub-second failure detection (~450ms)
- GigabitEthernet interfaces for data plane, G3 for management

## Project Structure

```
ibn-platform/
├── src/ibn/
│   ├── cli.py              # Click CLI commands (16 commands, multi-protocol)
│   ├── errors.py           # Exception hierarchy
│   ├── model/
│   │   ├── topology.py     # Pydantic topology models
│   │   ├── loader.py       # YAML → NetworkX graph
│   │   └── addressing.py   # IP address utilities
│   ├── intent/
│   │   ├── schema.py       # Intent & result models
│   │   └── parser.py       # Intent validation
│   ├── solver/
│   │   └── z3_solver.py    # Z3 constraint solver
│   ├── services/
│   │   ├── schema.py       # Service model definitions
│   │   └── registry.py     # Service type registry
│   ├── deploy/
│   │   ├── generator.py    # Config generation
│   │   ├── connector.py    # SSH device connector
│   │   ├── netconf.py      # NETCONF/RESTCONF connectors
│   │   └── diff.py         # Config diff engine
│   ├── viz/
│   │   └── topology.py     # ASCII topology diagrams
│   ├── monitor/
│   │   └── watcher.py      # Real-time network monitoring
│   ├── state/
│   │   └── history.py      # Deployment history & rollback
│   └── compliance/
│       └── checker.py      # Compliance monitoring & verification
├── tests/
│   └── unit/               # Unit tests (80 tests)
│       ├── test_compliance.py # Compliance checker tests
│       ├── test_history.py    # Deployment history tests
│       ├── test_intent.py     # Intent parser tests
│       ├── test_netconf.py    # NETCONF/RESTCONF tests
│       └── test_solver.py     # Z3 solver tests
├── templates/
│   ├── ios-xe/
│   │   └── bgp.j2          # BGP config template
│   └── bootstrap/
│       └── c8000v-base.j2  # Bootstrap config
├── examples/
│   ├── lab.yaml            # Lab topology
│   └── intents/
│       └── nyc-branch.yaml # Sample intent
└── pyproject.toml
```

## Technologies

- **Python 3.11+** - Core language
- **Z3 Solver** - Microsoft's SMT solver for constraint optimization
- **NetworkX** - Graph representation and analysis
- **Pydantic** - Data validation and settings
- **Click** - CLI framework
- **Rich** - Terminal formatting
- **Jinja2** - Config templating
- **Netmiko** - SSH device connections
- **ncclient** - NETCONF client for YANG-based config
- **requests** - RESTCONF REST API client

## Roadmap

- [x] Topology modeling with failure domains
- [x] Intent parsing and validation
- [x] Z3 constraint solver for diverse paths
- [x] BGP/BFD config generation
- [x] SSH deployment with Netmiko
- [x] What-if failure simulation
- [x] Topology visualization (ASCII diagrams)
- [x] Config diff before deployment
- [x] Real-time network monitoring
- [x] Deployment history tracking
- [x] Rollback capability
- [x] Unit test suite (80 tests)
- [x] Continuous compliance monitoring
- [x] NETCONF/RESTCONF support
- [ ] Web dashboard
- [ ] Multi-vendor templates

## License

MIT License - See LICENSE file for details.

## Author

Built as a portfolio project demonstrating Intent-Based Networking concepts with constraint-based optimization.
