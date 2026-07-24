# Architecture

## Overview

This example deploys an Azure network with an **Azure DNS Security Policy**
attached to the virtual network. Every DNS query originating from workloads in
the VNet is evaluated against ordered traffic rules before resolution,
preventing DNS-based information leakage (exfiltration and tunneling) and
providing full query visibility through logging.

## Diagram

```mermaid
flowchart TB
    subgraph VNet["Virtual Network (10.20.0.0/16)"]
        WL["Workload subnet<br/>10.20.1.0/24<br/>(VMs / AKS / App Service)"]
        RES["DNS Resolver inbound endpoint<br/>10.20.2.0/28"]
    end

    POL["DNS Security Policy<br/>(linked to VNet)"]

    subgraph RULES["Ordered traffic rules (lowest priority number wins)"]
        R1["100 · ALLOW<br/>allow-list domains"]
        R2["200 · BLOCK<br/>known exfil / C2 domains"]
        R3["300 · ALERT<br/>Microsoft threat-intel list"]
        R4["400 · BLOCK<br/>default-deny catch-all (.)"]
    end

    LAW["Log Analytics Workspace<br/>(DnsResponse logs)"]

    WL -->|DNS query| POL
    RES --> POL
    POL --> R1 --> R2 --> R3 --> R4
    POL -.->|diagnostic logs| LAW

    R1 -->|allowed| RESOLVE["Resolve query"]
    R2 -->|blocked| DROP["Query denied"]
    R4 -->|blocked| DROP
```

## Rule evaluation order

Rules are evaluated by **priority**, where the **lowest number has the highest
precedence**. This implements a default-deny (allow-list) posture:

| Priority | Action | Target | Purpose |
|----------|--------|--------|---------|
| 100 | Allow | Allow-list domain list | Permit approved business domains |
| 200 | Block | Block-list domain list | Explicitly deny known exfil / C2 / tunneling domains |
| 300 | Alert | Microsoft-managed threat-intel list | Log (don't block yet) on emerging malicious domains |
| 400 | Block | Wildcard `.` (all) | Default-deny — anything not allowed above is blocked |

## How it prevents DNS information leakage

1. **Default-deny** stops queries to arbitrary attacker-controlled domains,
   which is how DNS tunneling/exfiltration reaches its destination.
2. **Block-list + threat intel** covers known-bad and emerging domains.
3. **Alert mode** lets you observe impact before enforcing.
4. **Logging to Log Analytics** exposes exfiltration signals (long random
   subdomains, TXT/NULL records, high query volume). See
   [`hunting-queries.md`](./hunting-queries.md).

## Components

| Resource | Provider | Purpose |
|----------|----------|---------|
| Resource Group | azurerm | Container for all resources |
| Virtual Network + subnets | azurerm | Protected network + delegated resolver subnet |
| Private DNS Resolver + inbound endpoint | azurerm | Resolution path for hybrid/custom forwarding |
| DNS Security Policy | azapi | Top-level policy linked to the VNet |
| DNS Resolver Domain Lists | azapi | Allow / block / catch-all domain lists |
| DNS Security Rules | azapi | Ordered Allow / Block / Alert rules |
| VNet Link | azapi | Binds the policy to the VNet |
| Log Analytics Workspace + Diagnostic Setting | azurerm | DNS query logging |
