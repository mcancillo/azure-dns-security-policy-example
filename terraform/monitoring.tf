resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${var.name_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

# Ship DNS query/response logs from the DNS Security Policy to Log Analytics.
resource "azurerm_monitor_diagnostic_setting" "dns_policy" {
  name                       = "diag-dns-security"
  target_resource_id         = azapi_resource.dns_security_policy.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "DnsResponse"
  }
}

# ---------------------------------------------------------------------------
# GAP MITIGATION (detection -> response): onboard the workspace to Microsoft
# Sentinel and add an analytics rule + email alerting so DNS exfiltration
# signals generate incidents/notifications instead of sitting in raw logs.
# ---------------------------------------------------------------------------
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  workspace_id = azurerm_log_analytics_workspace.this.id
}

resource "azurerm_sentinel_alert_rule_scheduled" "long_subdomain" {
  name                       = "dns-tunneling-long-subdomain"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
  display_name               = "DNS tunneling - abnormally long subdomain labels"
  severity                   = "Medium"
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0

  query = <<-KQL
    DnsResponse
    | extend Label = tostring(split(QueryName, ".")[0])
    | where strlen(Label) > 40
    | project TimeGenerated, SourceIpAddress, QueryName, LabelLength = strlen(Label)
  KQL
}

# Action group used to notify the SOC.
resource "azurerm_monitor_action_group" "soc" {
  name                = "ag-soc-${var.name_prefix}"
  resource_group_name = azurerm_resource_group.this.name
  short_name          = "soc"

  email_receiver {
    name          = "soc-email"
    email_address = var.alert_email
  }

  tags = var.tags
}

# Alert when a spike of blocked DNS queries occurs (possible exfil attempt).
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "blocked_dns_spike" {
  name                = "alert-blocked-dns-spike"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location

  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"
  scopes               = [azurerm_log_analytics_workspace.this.id]
  severity             = 2

  criteria {
    query                   = <<-KQL
      DnsResponse
      | where ResponseCode == "Blocked" or Result == "Blocked"
      | summarize Count = count() by SourceIpAddress
    KQL
    time_aggregation_method = "Count"
    threshold               = 50
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.soc.id]
  }

  tags = var.tags
}
