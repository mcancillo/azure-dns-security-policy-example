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

# Azure Firewall subnet (name is mandatory and fixed).
resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.firewall_subnet_prefix]
}

# ---------------------------------------------------------------------------
# GAP MITIGATION (bypass prevention): NSG on the workload subnet denies direct
# DNS egress to the Internet. Hosts CANNOT reach external resolvers on UDP/TCP
# 53 or DoT (853), which forces them to use Azure-provided DNS that the DNS
# Security Policy inspects. This closes the "just query 8.8.8.8 / 1.1.1.1"
# and DoT bypass paths.
# ---------------------------------------------------------------------------
resource "azurerm_network_security_group" "workload" {
  name                = "nsg-workload-${var.name_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  security_rule {
    name                       = "Deny-External-DNS-UDP53"
    priority                   = 200
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }

  security_rule {
    name                       = "Deny-External-DNS-TCP53"
    priority                   = 210
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }

  security_rule {
    name                       = "Deny-External-DoT-853"
    priority                   = 220
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "853"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }
}

resource "azurerm_subnet_network_security_group_association" "workload" {
  subnet_id                 = azurerm_subnet.workload.id
  network_security_group_id = azurerm_network_security_group.workload.id
}

# ---------------------------------------------------------------------------
# Route all workload egress through Azure Firewall for inspection/logging and
# to enable FQDN-based application filtering (DoH mitigation lives there).
# ---------------------------------------------------------------------------
resource "azurerm_route_table" "workload" {
  name                = "rt-workload-${var.name_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = var.tags

  route {
    name                   = "default-via-firewall"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.this.ip_configuration[0].private_ip_address
  }
}

resource "azurerm_subnet_route_table_association" "workload" {
  subnet_id      = azurerm_subnet.workload.id
  route_table_id = azurerm_route_table.workload.id
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
