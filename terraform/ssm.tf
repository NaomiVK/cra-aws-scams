# AWS Systems Manager Parameter Store - Secrets Management

# Google Maps API Key
resource "aws_ssm_parameter" "google_maps_api_key" {
  count = var.google_maps_api_key != "" ? 1 : 0

  name        = "/cra-scam/GOOGLE_MAPS_API_KEY"
  description = "Google Maps API key for geo visualization"
  type        = "SecureString"
  value       = var.google_maps_api_key

  tags = {
    Name = "cra-scam-google-maps-key"
  }
}

# OpenAI API Key
resource "aws_ssm_parameter" "openai_api_key" {
  count = var.openai_api_key != "" ? 1 : 0

  name        = "/cra-scam/OPENAI_API_KEY"
  description = "OpenAI API key for embeddings"
  type        = "SecureString"
  value       = var.openai_api_key

  tags = {
    Name = "cra-scam-openai-key"
  }
}

# Google Search Console Service Account
resource "aws_ssm_parameter" "gsc_service_account" {
  count = var.gsc_service_account != "" ? 1 : 0

  name        = "/cra-scam/GSC_SERVICE_ACCOUNT"
  description = "Google Search Console service account JSON"
  type        = "SecureString"
  value       = var.gsc_service_account

  tags = {
    Name = "cra-scam-gsc-service-account"
  }
}
