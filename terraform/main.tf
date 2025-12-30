terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "cra-scam-terraform-state"
    key            = "terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "cra-scam-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
}
