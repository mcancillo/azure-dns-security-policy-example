resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${var.name_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

# Ship DNS query/response logs from the DNS Security Policy to Log Analytics.
# This gives visibility into exfiltration signals: high-volume queries,
# long/random subdomains, and unusual record types (TXT/NULL).
resource "azurerm_monitor_diagnostic_setting" "dns_policy" {
  name                       = "diag-dns-security"
  target_resource_id         = azapi_resource.dns_security_policy.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "DnsResponse"
  }
}
