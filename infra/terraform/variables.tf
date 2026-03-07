variable "prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "tahini-sidecar"
}

variable "location" {
  description = "Azure region. Must support DCsv3 VMs (confidential computing)."
  type        = string
  default     = "eastus"
}

variable "vm_size" {
  description = "Azure VM size. Use a DCsv3 SKU for SGX support."
  type        = string
  default     = "Standard_DC1s_v3"
}

variable "admin_username" {
  description = "SSH admin username on the VM"
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key to deploy on the VM"
  type        = string
  default     = "~/.ssh/tahini-sidecar_key.pub"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to SSH into the VM (set to your IP for security)"
  type        = string
  default     = "*"
}

variable "os_disk_size_gb" {
  description = "OS disk size in GB"
  type        = number
  default     = 64
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    project = "tahini-sidecar"
  }
}
