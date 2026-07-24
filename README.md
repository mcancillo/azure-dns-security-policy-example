# Azure DNS Security Policy — Example Architecture

Terraform example that prevents **DNS information leakage** (exfiltration and
tunneling) using an [Azure DNS Security Policy](https://learn.microsoft.com/en-us/azure/dns/dns-security-policy)
linked to a virtual network, with allow/block/alert rules, Microsoft threat
intelligence, and full DNS query logging.

## What gets deployed

- **Resource group**, **virtual network** with a workload subnet and a delegated
  subnet for the DNS Resolver inbound endpoint.
- **Azure Private DNS Resolver** + inbound endpoint (resolution path for
  hybrid / custom forwarding scenarios).
- **DNS Security Policy** linked to the VNet, so *all* VNet DNS traffic is
  inspected.
- **Domain lists** (allow / block / catch-all) and **DNS security rules** that
  implement a **default-deny (allow-list)** posture.
- **Log Analytics workspace** + diagnostic setting streaming `DnsResponse` logs
  for exfiltration hunting.

See [`docs/architecture.md`](docs/architecture.md) for the diagram and rule
model, and [`docs/hunting-queries.md`](docs/hunting-queries.md) for KQL.

## Default-deny rule model

| Priority | Action | Target |
|----------|--------|--------|
| 100 | Allow | Approved (allow-list) domains |
| 200 | Block | Known exfil / C2 / tunneling domains |
| 300 | Alert | Microsoft-managed threat-intel list |
| 400 | Block | Everything else (wildcard `.`) |

> Rules are evaluated by priority — **the lowest number wins**.

## Why `azapi`

DNS Security Policy resource types
(`Microsoft.Network/dnsResolverPolicies*`, `dnsResolverDomainLists`) are not yet
in the `azurerm` provider, so they are deployed with the
[`azapi`](https://registry.terraform.io/providers/Azure/azapi/latest) provider.
Standard networking and logging use `azurerm`.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (`az login`)
- A subscription where the DNS Security Policy feature is available in your region

## Usage

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # then edit values

az login
az account set --subscription "<your-subscription-id>"

terraform init
terraform plan
terraform apply
```

After apply, set the workload VNet / VM custom DNS server to the resolver
inbound endpoint IP (see `terraform output`).

## Customizing the policy

- Edit `allowlist_domains` / `blocklist_domains` in `terraform.tfvars`
  (domains must end with a trailing dot, e.g. `example.com.`).
- Start rule 300 in **Alert** mode, review logs, then switch to **Block** once
  you're confident it won't disrupt legitimate traffic.
- Scope wildcards carefully to avoid blocking CDNs / SaaS dependencies.

## Clean up

```bash
terraform destroy
```

## Notes

- The `azapi` API version (`2025-10-01-preview`) and the managed threat-intel
  list identifier may change as the feature moves toward GA — verify against
  current Microsoft docs before production use.
- This is an **example / reference** architecture, not a hardened production
  module.
