variable "location" {
  type        = string
  description = "Azure region for all resources."
  default     = "eastus"
}

variable "resource_group_name" {
  type        = string
  description = "Name of the resource group to create."
  default     = "rg-dns-security-example"
}

variable "name_prefix" {
  type        = string
  description = "Prefix used to name resources."
  default     = "dnssec"
}

variable "vnet_address_space" {
  type        = list(string)
  description = "Address space for the virtual network."
  default     = ["10.20.0.0/16"]
}

variable "workload_subnet_prefix" {
  type        = string
  description = "Address prefix for the workload subnet."
  default     = "10.20.1.0/24"
}

variable "resolver_inbound_subnet_prefix" {
  type        = string
  description = "Delegated subnet for the Private DNS Resolver inbound endpoint."
  default     = "10.20.2.0/28"
}

variable "firewall_subnet_prefix" {
  type        = string
  description = "Address prefix for AzureFirewallSubnet (must be /26 or larger)."
  default     = "10.20.3.0/26"
}

# ---------------------------------------------------------------------------
# Allow-list. Tightened to SPECIFIC FQDNs (no broad *.windows.net / *.azure.com
# parents that could be abused as exfil channels, e.g. attacker.blob.core.windows.net).
# Domains must end with a trailing dot.
# ---------------------------------------------------------------------------
variable "allowlist_domains" {
  type        = list(string)
  description = "Specific business FQDNs that are explicitly allowed to resolve. Keep these narrow."
  default = [
    "api.contoso.com.",
    "app.contoso.com.",
  ]
}

# Platform FQDNs the Azure control plane / guest agents need so that the
# default-deny rule does not break the environment. Kept separate so security
# and platform teams can own their lists independently.
variable "platform_allowlist_domains" {
  type        = list(string)
  description = "Azure platform FQDNs required for management/agent connectivity. Trailing dot required."
  default = [
    "login.microsoftonline.com.",
    "management.azure.com.",
    "management.core.windows.net.",
    "packages.microsoft.com.",
    "azure.archive.ubuntu.com.",
  ]
}

variable "blocklist_domains" {
  type        = list(string)
  description = "Known-bad / exfiltration / tunneling domains to block. Must end with a trailing dot."
  default = [
    "malicious-exfil.example.",
    "tunnel-c2.example.",
    "data-leak.example.",
  ]
}

variable "log_retention_days" {
  type        = number
  description = "Retention (days) for the Log Analytics workspace. >=90 recommended for IR/compliance."
  default     = 90
}

variable "alert_email" {
  type        = string
  description = "Email address that receives Sentinel/Monitor alerts for DNS security events."
  default     = "soc@contoso.com"
}

variable "enable_resource_lock" {
  type        = bool
  description = "Apply a CanNotDelete lock on the DNS Security Policy to resist tampering."
  default     = true
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default = {
    project = "dns-security-policy-example"
    owner   = "platform-security"
    env     = "demo"
  }
}
