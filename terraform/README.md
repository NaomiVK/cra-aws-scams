# Terraform Infrastructure

This directory contains Terraform configuration for the CRA Scam Detection Dashboard AWS infrastructure.

## Prerequisites

1. **Install Terraform**: https://developer.hashicorp.com/terraform/downloads
2. **AWS CLI configured** with credentials: `aws configure`
3. **EC2 Key Pair** created in AWS Console

## Quick Start

```bash
# 1. Navigate to terraform directory
cd terraform

# 2. Create your variables file
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# 3. Initialize Terraform
terraform init

# 4. Preview changes
terraform plan

# 5. Apply changes
terraform apply
```

## Files

| File | Description |
|------|-------------|
| `main.tf` | Provider config, data sources |
| `variables.tf` | Input variable definitions |
| `outputs.tf` | Output values (IPs, URLs, etc.) |
| `ec2.tf` | EC2 instance and security group |
| `dynamodb.tf` | DynamoDB tables |
| `iam.tf` | IAM roles and policies |
| `ssm.tf` | Parameter Store secrets |
| `terraform.tfvars.example` | Example variables (copy to terraform.tfvars) |

## Resources Created

- **EC2 Instance** - Runs the Node.js application
- **Security Group** - Firewall rules (SSH, HTTP, HTTPS, app ports)
- **IAM Role** - Permissions for EC2 to access AWS services
- **DynamoDB Table** - Stores admin-added seed phrases
- **SSM Parameters** - Securely stores API keys

## Common Commands

```bash
# See what will change
terraform plan

# Apply changes
terraform apply

# Destroy everything (careful!)
terraform destroy

# Format code
terraform fmt

# Validate configuration
terraform validate

# Show current state
terraform show

# List resources
terraform state list
```

## Importing Existing Resources

If you already have resources created manually, import them:

```bash
# Import existing DynamoDB table
terraform import aws_dynamodb_table.seed_phrases cra-scam-seed-phrases

# Import existing EC2 instance
terraform import aws_instance.app_server i-1234567890abcdef0

# Import existing IAM role
terraform import aws_iam_role.ec2_role cra-scam-detection-ec2-role
```

## Secrets Management

Secrets can be provided via:

1. **terraform.tfvars** (gitignored):
   ```hcl
   openai_api_key = "sk-..."
   ```

2. **Environment variables**:
   ```bash
   export TF_VAR_openai_api_key="sk-..."
   terraform apply
   ```

3. **AWS Console** (set Parameter Store values manually, skip the ssm.tf resources)

## Cost Estimate

| Resource | Approximate Cost |
|----------|------------------|
| t2.small EC2 (24/7) | ~$17/month |
| DynamoDB (on-demand) | ~$0.25/month |
| SSM Parameters | Free |
| **Total** | **~$17-20/month** |

## Notes

- EC2 IP changes on stop/start (uncomment Elastic IP in ec2.tf for static IP)
- State file contains secrets - don't commit it!
- For team use, consider S3 backend for state (see main.tf comments)
