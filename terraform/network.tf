resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-${var.name_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = var.vnet_address_space
  tags                = var.tags
}

# Subnet hosting the protected workloads (VMs, App Service integration, AKS, etc.)
resource "azurerm_subnet" "workload" {
  name                 = "snet-workload"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.workload_subnet_prefix]
}

# Delegated subnet required by the Private DNS Resolver inbound endpoint.
resource "azurerm_subnet" "resolver_inbound" {
  name                 = "snet-resolver-inbound"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.resolver_inbound_subnet_prefix]

  delegation {
    name = "Microsoft.Network.dnsResolvers"
    service_delegation {
      name    = "Microsoft.Network/dnsResolvers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Azure Private DNS Resolver. DNS Security Policies evaluate the queries that
# flow through the VNet; the resolver provides the resolution path for
# on-prem / hybrid and custom conditional forwarding scenarios.
resource "azurerm_private_dns_resolver" "this" {
  name                = "pdnsr-${var.name_prefix}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  virtual_network_id  = azurerm_virtual_network.this.id
  tags                = var.tags
}

resource "azurerm_private_dns_resolver_inbound_endpoint" "this" {
  name                    = "inbound-${var.name_prefix}"
  private_dns_resolver_id = azurerm_private_dns_resolver.this.id
  location                = azurerm_resource_group.this.location

  ip_configurations {
    private_ip_allocation_method = "Dynamic"
    subnet_id                    = azurerm_subnet.resolver_inbound.id
  }

  tags = var.tags
}
