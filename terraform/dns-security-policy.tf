# ---------------------------------------------------------------------------
# Azure DNS Security Policy
#
# Deployed via azapi because these resource types are not yet available in the
# azurerm provider. The policy is linked to the VNet, so ALL DNS traffic from
# the VNet is evaluated against the ordered traffic rules below.
#
# Rule evaluation is by priority: the LOWEST priority number wins (highest
# precedence). Hardened ordering — malicious domains are blocked BEFORE any
# allow rule, so a compromised/allow-listed-by-mistake domain cannot be used:
#   100 -> Block known-bad / exfiltration domains
#   110 -> Block Microsoft-managed threat-intel domains
#   200 -> Allow approved business domains
#   210 -> Allow required Azure platform domains
#   400 -> Block everything else (default-deny catch-all)
# ---------------------------------------------------------------------------

locals {
  api_version = "2025-10-01-preview"
}

resource "azapi_resource" "dns_security_policy" {
  type      = "Microsoft.Network/dnsResolverPolicies@${local.api_version}"
  name      = "dnspol-${var.name_prefix}"
  parent_id = azurerm_resource_group.this.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {}
  }

  response_export_values = ["id", "name"]
}

# Link the policy to the virtual network. All DNS queries originating in the
# VNet are now governed by this policy.
resource "azapi_resource" "vnet_link" {
  type      = "Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks@${local.api_version}"
  name      = "vnetlink-${var.name_prefix}"
  parent_id = azapi_resource.dns_security_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      virtualNetwork = {
        id = azurerm_virtual_network.this.id
      }
    }
  }
}

# Business allow-list domain list (narrow, specific FQDNs).
resource "azapi_resource" "domain_list_allow" {
  type      = "Microsoft.Network/dnsResolverDomainLists@${local.api_version}"
  name      = "dl-allow-${var.name_prefix}"
  parent_id = azurerm_resource_group.this.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      domains = var.allowlist_domains
    }
  }
}

# Azure platform allow-list domain list (management/agent connectivity).
resource "azapi_resource" "domain_list_platform" {
  type      = "Microsoft.Network/dnsResolverDomainLists@${local.api_version}"
  name      = "dl-platform-${var.name_prefix}"
  parent_id = azurerm_resource_group.this.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      domains = var.platform_allowlist_domains
    }
  }
}

# Block-list domain list (known exfiltration / C2 / tunneling domains).
resource "azapi_resource" "domain_list_block" {
  type      = "Microsoft.Network/dnsResolverDomainLists@${local.api_version}"
  name      = "dl-block-${var.name_prefix}"
  parent_id = azurerm_resource_group.this.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      domains = var.blocklist_domains
    }
  }
}

# Catch-all domain list (wildcard) used by the default-deny rule.
resource "azapi_resource" "domain_list_all" {
  type      = "Microsoft.Network/dnsResolverDomainLists@${local.api_version}"
  name      = "dl-all-${var.name_prefix}"
  parent_id = azurerm_resource_group.this.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      domains = ["."]
    }
  }
}

# Rule 100: BLOCK known exfiltration / C2 domains (highest precedence).
resource "azapi_resource" "rule_block" {
  type      = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@${local.api_version}"
  name      = "rule-block-known-bad"
  parent_id = azapi_resource.dns_security_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      priority             = 100
      dnsSecurityRuleState = "Enabled"
      action = {
        actionType = "Block"
      }
      dnsResolverDomainLists = [
        { id = azapi_resource.domain_list_block.id }
      ]
    }
  }
}

# Rule 110: BLOCK Microsoft-managed threat-intelligence domains.
# (Hardened from Alert -> Block so known-malicious domains do not resolve.)
resource "azapi_resource" "rule_block_ti" {
  type      = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@${local.api_version}"
  name      = "rule-block-threatintel"
  parent_id = azapi_resource.dns_security_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      priority             = 110
      dnsSecurityRuleState = "Enabled"
      action = {
        actionType = "Block"
      }
      managedDomainLists = [
        { id = "AzureManagedDomainListThreatIntel" }
      ]
    }
  }
}

# Rule 200: ALLOW approved business domains.
resource "azapi_resource" "rule_allow" {
  type      = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@${local.api_version}"
  name      = "rule-allow-approved"
  parent_id = azapi_resource.dns_security_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      priority             = 200
      dnsSecurityRuleState = "Enabled"
      action = {
        actionType = "Allow"
      }
      dnsResolverDomainLists = [
        { id = azapi_resource.domain_list_allow.id }
      ]
    }
  }
}

# Rule 210: ALLOW required Azure platform domains (prevents default-deny from
# breaking control-plane / guest-agent connectivity).
resource "azapi_resource" "rule_allow_platform" {
  type      = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@${local.api_version}"
  name      = "rule-allow-platform"
  parent_id = azapi_resource.dns_security_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      priority             = 210
      dnsSecurityRuleState = "Enabled"
      action = {
        actionType = "Allow"
      }
      dnsResolverDomainLists = [
        { id = azapi_resource.domain_list_platform.id }
      ]
    }
  }
}

# Rule 400: default-deny catch-all. Any domain not explicitly allowed above
# is blocked, closing the door on arbitrary DNS exfiltration destinations.
resource "azapi_resource" "rule_block_all" {
  type      = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@${local.api_version}"
  name      = "rule-block-default-deny"
  parent_id = azapi_resource.dns_security_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      priority             = 400
      dnsSecurityRuleState = "Enabled"
      action = {
        actionType = "Block"
      }
      dnsResolverDomainLists = [
        { id = azapi_resource.domain_list_all.id }
      ]
    }
  }
}
