# IAM Roles and Policies for EC2

# IAM Role for EC2 instance
resource "aws_iam_role" "ec2_role" {
  name = "cra-scam-detection-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Instance profile (required to attach role to EC2)
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "cra-scam-detection-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# Policy: DynamoDB access for seed phrases
resource "aws_iam_role_policy" "dynamodb_policy" {
  name = "dynamodb-seed-phrases-access"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBSeedPhrases"
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.seed_phrases.arn
      }
    ]
  })
}

# Policy: SSM Parameter Store access for secrets
resource "aws_iam_role_policy" "ssm_policy" {
  name = "ssm-parameter-store-access"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SSMParameterAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/cra-scam/*"
      }
    ]
  })
}

# Policy: CloudWatch Logs (for future logging)
resource "aws_iam_role_policy" "cloudwatch_policy" {
  name = "cloudwatch-logs-access"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/cra-scam-detection/*"
      }
    ]
  })
}
