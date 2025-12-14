# DynamoDB Tables

# Seed Phrases table - stores admin-added keywords for embedding detection
resource "aws_dynamodb_table" "seed_phrases" {
  name         = "cra-scam-seed-phrases"
  billing_mode = "PAY_PER_REQUEST"  # On-demand pricing (no capacity planning needed)

  hash_key  = "category"  # Partition key
  range_key = "term"      # Sort key

  attribute {
    name = "category"
    type = "S"
  }

  attribute {
    name = "term"
    type = "S"
  }

  # Enable point-in-time recovery for data protection
  point_in_time_recovery {
    enabled = true
  }

  # Server-side encryption
  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "cra-scam-seed-phrases"
  }
}

# Optional: Future tables for caching or analytics
# resource "aws_dynamodb_table" "analytics_cache" {
#   name         = "cra-scam-analytics-cache"
#   billing_mode = "PAY_PER_REQUEST"
#   hash_key     = "cache_key"
#
#   attribute {
#     name = "cache_key"
#     type = "S"
#   }
#
#   ttl {
#     attribute_name = "expires_at"
#     enabled        = true
#   }
# }
