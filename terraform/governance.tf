# ---------------------------------------------------------------------------
# GAP MITIGATION (tamper resistance / governance)
# ---------------------------------------------------------------------------

# CanNotDelete lock on the DNS Security Policy so a compromised Contributor
# cannot simply delete the control. (Modifications should be gated by RBAC/PIM
# and detected by the Azure Policy below.)
resource "azurerm_management_lock" "dns_policy" {
  count      = var.enable_resource_lock ? 1 : 0
  name       = "lock-dns-security-policy"
  scope      = azapi_resource.dns_security_policy.id
  lock_level = "CanNotDelete"
  notes      = "Protects the DNS Security Policy from accidental or malicious deletion."
}

# Azure Policy that AUDITS any DNS security rule that is not Enabled. If an
# attacker or misconfiguration disables a rule (dnsSecurityRuleState=Disabled),
# it becomes non-compliant and visible in Azure Policy compliance / Defender.
resource "azurerm_policy_definition" "dns_rules_enabled" {
  name         = "audit-dns-security-rules-enabled"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "DNS security rules must be Enabled"
  description  = "Audits DNS resolver policy security rules that are not in the Enabled state."

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules"
        },
        {
          field    = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules/dnsSecurityRuleState"
          notEquals = "Enabled"
        }
      ]
    }
    then = {
      effect = "audit"
    }
  })
}

resource "azurerm_resource_group_policy_assignment" "dns_rules_enabled" {
  name                 = "audit-dns-rules-enabled"
  resource_group_id    = azurerm_resource_group.this.id
  policy_definition_id = azurerm_policy_definition.dns_rules_enabled.id
  display_name         = "Audit DNS security rules are Enabled"
}
