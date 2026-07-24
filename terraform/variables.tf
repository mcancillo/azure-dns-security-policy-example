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

variable "allowlist_domains" {
  type        = list(string)
  description = "Fully-qualified domains that are explicitly allowed. Must end with a trailing dot."
  default = [
    "microsoft.com.",
    "windows.net.",
    "azure.com.",
    "github.com.",
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
  description = "Retention (days) for the Log Analytics workspace."
  default     = 30
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
