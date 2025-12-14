# Input variables for the infrastructure

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.small"
}

variable "key_pair_name" {
  description = "Name of the EC2 key pair for SSH access"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed for SSH access (your IP)"
  type        = string
  default     = "0.0.0.0/0"  # Restrict this to your IP in production!
}

variable "app_port" {
  description = "Port the application runs on"
  type        = number
  default     = 3000
}

variable "frontend_port" {
  description = "Port for frontend (if serving separately)"
  type        = number
  default     = 4200
}

# Secrets (sensitive - don't commit values to git!)
variable "google_maps_api_key" {
  description = "Google Maps API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "openai_api_key" {
  description = "OpenAI API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "gsc_service_account" {
  description = "Google Search Console service account JSON"
  type        = string
  sensitive   = true
  default     = ""
}
