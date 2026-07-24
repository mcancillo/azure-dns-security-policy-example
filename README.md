# Azure DNS Security Policy — Hardened Example Architecture

Terraform example that prevents **DNS information leakage** (exfiltration and
tunneling) using an [Azure DNS Security Policy](https://learn.microsoft.com/en-us/azure/dns/dns-security-policy)
linked to a virtual network — hardened with layered egress controls,
detection/response, and governance guardrails.

## What gets deployed

- **VNet** with workload, DNS-resolver, and Azure Firewall subnets.
- **DNS Security Policy** linked to the VNet with a hardened, ordered rule set
  (block-first, default-deny).
- **NSG + UDR + Azure Firewall** that force DNS through the inspected path and
  block bypass channels (external resolvers, DoT, DoH).
- **Private DNS Resolver** inbound endpoint for hybrid/custom resolution.
- **Log Analytics + Microsoft Sentinel** with an analytics rule and email
  alerting.
- **Management lock + Azure Policy** to resist and detect tampering.

See [`docs/architecture.md`](docs/architecture.md) for the diagram and the full
**gap-to-mitigation mapping**, [`docs/validation.md`](docs/validation.md) for a
bypass/exfil test harness, and [`docs/hunting-queries.md`](docs/hunting-queries.md)
for KQL.

## Hardened rule model (lowest number wins)

| Priority | Action | Target |
|----------|--------|--------|
| 100 | Block | Known exfil / C2 / tunneling domains |
| 110 | Block | Microsoft-managed threat-intel list |
| 200 | Allow | Approved business FQDNs (narrow) |
| 210 | Allow | Required Azure platform FQDNs |
| 400 | Block | Everything else (wildcard `.`) |

## Defense-in-depth layers

1. **DNS Security Policy** — filters VNet DNS (block-first, default-deny).
2. **NSG** — denies direct external DNS (UDP/TCP 53, DoT 853) → no resolver bypass.
3. **Azure Firewall** — FQDN allow-list on 443 blocks DoH tunneling; DNS proxy + logs.
4. **Sentinel + alerts** — detects tunneling/exfil and notifies the SOC.
5. **Lock + Azure Policy** — prevents deletion and audits disabled rules.

## Why `azapi`

DNS Security Policy resource types (`Microsoft.Network/dnsResolverPolicies*`,
`dnsResolverDomainLists`) are not yet in the `azurerm` provider, so they are
deployed with [`azapi`](https://registry.terraform.io/providers/Azure/azapi/latest).
Networking, firewall, logging, and governance use `azurerm`.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (`az login`)
- A subscription where the DNS Security Policy feature is available in your region

## Usage

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # then edit values
# (optional) cp backend.tf.example backend.tf  # for remote state

az login
az account set --subscription "<your-subscription-id>"

terraform init
terraform plan
terraform apply
```

Validate the controls with [`docs/validation.md`](docs/validation.md).

## CI

[`.github/workflows/terraform-ci.yml`](.github/workflows/terraform-ci.yml) runs
`terraform fmt`, `validate`, and **tfsec** + **checkov** IaC security scans on
every push/PR.

## Block-list / threat intelligence

The custom block-list should be **generated from credible, maintained feeds**,
not hand-curated. See [`intel/sources.md`](intel/sources.md) for the recommended
sources (abuse.ch URLhaus/ThreatFox/Feodo, Spamhaus, OpenPhish, SANS ISC) and
[`intel/blocklist.example.txt`](intel/blocklist.example.txt) for a categorized
example (reserved placeholders + cited historical sinkholed domains).

Generate an enforceable list from live feeds into the Terraform-read file:

```bash
# Linux / CI
./scripts/build-blocklist.sh > terraform/blocklist.generated.txt
```
```powershell
# Windows
./scripts/build-blocklist.ps1 | Out-File terraform/blocklist.generated.txt -Encoding utf8
```

Terraform reads [`terraform/blocklist.generated.txt`](terraform/blocklist.generated.txt)
and **unions** it with `blocklist_domains`. A scheduled workflow
([`.github/workflows/refresh-blocklist.yml`](.github/workflows/refresh-blocklist.yml))
runs the builder daily and **opens a PR** with the refreshed list for review.
Rule 110 additionally blocks Microsoft's managed threat-intel list with zero
maintenance.

## Customizing the policy

- Edit `allowlist_domains` / `platform_allowlist_domains` / `blocklist_domains`
  in `terraform.tfvars` (domains must end with a trailing dot, e.g. `example.com.`).
- Keep the business allow-list **narrow** (specific FQDNs) to avoid creating
  exfil channels via broad cloud parents like `*.blob.core.windows.net`.
- Add required platform FQDNs before enabling in production so default-deny does
  not break control-plane connectivity.

## Clean up

```bash
# Resource lock must be removed first if enabled.
terraform destroy
```

## Notes & caveats

- The `azapi` API version (`2025-10-01-preview`) and the managed threat-intel
  list identifier (`AzureManagedDomainListThreatIntel`) may change toward GA —
  verify against current Microsoft docs before production use.
- Log table/column names (`DnsResponse`, `ResponseCode`, etc.) depend on the
  schema streamed to your workspace; adjust queries accordingly.
- This is a **reference** architecture. It was authored without a local
  `terraform validate` run (Terraform not installed in the authoring env) — run
  `terraform init && validate` (and the CI) before deploying.
