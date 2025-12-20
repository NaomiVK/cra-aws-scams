variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Environment name (dev or prod)"
  type        = string

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be 'dev' or 'prod'."
  }
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for frontend hosting"
  type        = string
}

variable "api_domain" {
  description = "Domain name of the EC2 API server"
  type        = string
}

variable "api_port" {
  description = "Port the API server runs on"
  type        = number
  default     = 3000
}
