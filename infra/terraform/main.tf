terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ---------------------------------------------------------------------------
# Resource group
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "tahini" {
  name     = "${var.prefix}-rg"
  location = var.location
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
resource "azurerm_virtual_network" "tahini" {
  name                = "${var.prefix}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.tahini.location
  resource_group_name = azurerm_resource_group.tahini.name
}

resource "azurerm_subnet" "tahini" {
  name                 = "${var.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.tahini.name
  virtual_network_name = azurerm_virtual_network.tahini.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_public_ip" "tahini" {
  name                = "${var.prefix}-pip"
  location            = azurerm_resource_group.tahini.location
  resource_group_name = azurerm_resource_group.tahini.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "tahini" {
  name                = "${var.prefix}-nsg"
  location            = azurerm_resource_group.tahini.location
  resource_group_name = azurerm_resource_group.tahini.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_ssh_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "tahini" {
  name                = "${var.prefix}-nic"
  location            = azurerm_resource_group.tahini.location
  resource_group_name = azurerm_resource_group.tahini.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.tahini.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.tahini.id
  }
}

resource "azurerm_network_interface_security_group_association" "tahini" {
  network_interface_id      = azurerm_network_interface.tahini.id
  network_security_group_id = azurerm_network_security_group.tahini.id
}

# ---------------------------------------------------------------------------
# SGX-capable VM  (DCsv3 series)
# ---------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "tahini" {
  name                  = "${var.prefix}-vm"
  location              = azurerm_resource_group.tahini.location
  resource_group_name   = azurerm_resource_group.tahini.name
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.tahini.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    name                 = "${var.prefix}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml", {
    admin_username = var.admin_username
    github_repo    = var.github_repo
  }))

  tags = var.tags
}
