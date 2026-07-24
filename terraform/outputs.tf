output "resource_group_name" {
  description = "Resource group containing the deployment."
  value       = azurerm_resource_group.this.name
}

output "virtual_network_id" {
  description = "ID of the protected virtual network."
  value       = azurerm_virtual_network.this.id
}

output "dns_security_policy_id" {
  description = "ID of the DNS Security Policy."
  value       = azapi_resource.dns_security_policy.id
}

output "private_dns_resolver_inbound_ip" {
  description = "Private IP config of the DNS Resolver inbound endpoint."
  value       = azurerm_private_dns_resolver_inbound_endpoint.this.ip_configurations
}

output "firewall_private_ip" {
  description = "Private IP of Azure Firewall (next hop for workload egress)."
  value       = azurerm_firewall.this.ip_configuration[0].private_ip_address
}

output "firewall_public_ip" {
  description = "Public IP of Azure Firewall."
  value       = azurerm_public_ip.firewall.ip_address
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace receiving DNS and firewall logs."
  value       = azurerm_log_analytics_workspace.this.id
}
