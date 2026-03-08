output "public_ip" {
  description = "Public IP address of the VM"
  value       = azurerm_public_ip.tahini.ip_address
}

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value       = "ssh -i ${var.ssh_private_key_path} ${var.admin_username}@${azurerm_public_ip.tahini.ip_address}"
}

output "sync_command" {
  description = "Sync the repo to the VM using the existing infra/sync.sh"
  value       = "infra/sync.sh ${azurerm_public_ip.tahini.ip_address}"
}

output "resource_group" {
  description = "Name of the resource group (for manual cleanup)"
  value       = azurerm_resource_group.tahini.name
}
