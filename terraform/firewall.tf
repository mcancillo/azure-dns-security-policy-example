# ---------------------------------------------------------------------------
# Azure Firewall — defense in depth for egress and DoH mitigation.
#
# - DNS proxy enabled so the firewall can log and enforce on DNS.
# - Application rules restrict outbound HTTPS to an approved FQDN list, which
#   blocks DNS-over-HTTPS (DoH) to public resolvers (e.g. cloudflare-dns.com,
#   dns.google) that would otherwise tunnel around the DNS Security Policy.
# - Network rules deny raw DNS (53/853) egress as belt-and-suspenders.
# ---------------------------------------------------------------------------

resource "azurerm_public_ip" "firewall" {
  name                = "pip-fw-${var.name_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_firewall_policy" "this" {
  name                     = "fwpol-${var.name_prefix}"
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  sku                      = "Standard"
  threat_intelligence_mode = "Deny"
  tags                     = var.tags

  dns {
    proxy_enabled = true
  }
}

resource "azurerm_firewall_policy_rule_collection_group" "egress" {
  name               = "rcg-egress"
  firewall_policy_id = azurerm_firewall_policy.this.id
  priority           = 500

  # Allow only approved HTTPS destinations. Public DoH resolvers are NOT in this
  # list, so DoH-based DNS tunneling is blocked by default-deny.
  application_rule_collection {
    name     = "arc-allow-approved-https"
    priority = 100
    action   = "Allow"

    rule {
      name             = "approved-fqdns"
      source_addresses = [var.workload_subnet_prefix]
      destination_fqdns = [
        "api.contoso.com",
        "app.contoso.com",
        "login.microsoftonline.com",
        "management.azure.com",
        "packages.microsoft.com",
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
  }

  # Explicitly deny known public DoH provider FQDNs (defense in depth even if
  # the allow-list above is later loosened).
  application_rule_collection {
    name     = "arc-deny-doh"
    priority = 110
    action   = "Deny"

    rule {
      name             = "deny-public-doh"
      source_addresses = ["*"]
      destination_fqdns = [
        "cloudflare-dns.com",
        "dns.google",
        "dns.quad9.net",
        "doh.opendns.com",
        "mozilla.cloudflare-dns.com",
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
  }

  # Deny raw DNS egress (UDP/TCP 53 and DoT 853) to the Internet.
  network_rule_collection {
    name     = "nrc-deny-external-dns"
    priority = 200
    action   = "Deny"

    rule {
      name                  = "deny-dns-53-853"
      source_addresses      = ["*"]
      destination_addresses = ["*"]
      destination_ports     = ["53", "853"]
      protocols             = ["TCP", "UDP"]
    }
  }
}

resource "azurerm_firewall" "this" {
  name                = "afw-${var.name_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id  = azurerm_firewall_policy.this.id
  tags                = var.tags

  ip_configuration {
    name                 = "fw-ipconfig"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }
}

# Firewall diagnostics to Log Analytics (egress + DNS proxy visibility).
resource "azurerm_monitor_diagnostic_setting" "firewall" {
  name                       = "diag-firewall"
  target_resource_id         = azurerm_firewall.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category_group = "allLogs"
  }

  metric {
    category = "AllMetrics"
  }
}
