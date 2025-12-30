# DynamoDB tables for CRA Scam Detection

# Seed phrases table - stores keywords and seed phrases for detection
resource "aws_dynamodb_table" "seed_phrases" {
  name         = "cra-scam-seed-phrases"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "category"
  range_key = "term"

  attribute {
    name = "category"
    type = "S"
  }

  attribute {
    name = "term"
    type = "S"
  }

  tags = {
    Project     = "cra-scam-detection"
    Environment = var.environment
  }
}

# Reddit posts table - stores fetched Reddit posts with sentiment
resource "aws_dynamodb_table" "reddit_posts" {
  name         = "cra-reddit-posts"
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "subreddit"
  range_key = "reddit_id"

  attribute {
    name = "subreddit"
    type = "S"
  }

  attribute {
    name = "reddit_id"
    type = "S"
  }

  tags = {
    Project     = "cra-scam-detection"
    Environment = var.environment
  }
}

# Outputs
output "seed_phrases_table_arn" {
  description = "ARN of the seed phrases DynamoDB table"
  value       = aws_dynamodb_table.seed_phrases.arn
}

output "reddit_posts_table_arn" {
  description = "ARN of the Reddit posts DynamoDB table"
  value       = aws_dynamodb_table.reddit_posts.arn
}
