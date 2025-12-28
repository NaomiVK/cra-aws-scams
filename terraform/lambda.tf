# Lambda function to trigger daily Reddit fetch
# Calls the existing API endpoint POST /api/reddit/fetch

# IAM Role for Lambda
resource "aws_iam_role" "reddit_fetch_lambda" {
  name = "cra-scam-reddit-fetch-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# CloudWatch Logs policy
resource "aws_iam_role_policy_attachment" "reddit_fetch_lambda_logs" {
  role       = aws_iam_role.reddit_fetch_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda function
resource "aws_lambda_function" "reddit_fetch" {
  filename         = data.archive_file.reddit_fetch_lambda.output_path
  function_name    = "cra-scam-reddit-daily-fetch"
  role             = aws_iam_role.reddit_fetch_lambda.arn
  handler          = "index.handler"
  source_code_hash = data.archive_file.reddit_fetch_lambda.output_base64sha256
  runtime          = "nodejs20.x"
  timeout          = 300 # 5 minutes - Reddit API can be slow
  memory_size      = 256

  environment {
    variables = {
      API_URL     = "http://${var.api_domain}:${var.api_port}"
      FETCH_LIMIT = "20"
    }
  }
}

# Package the Lambda code
data "archive_file" "reddit_fetch_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/reddit-fetch"
  output_path = "${path.module}/lambda/reddit-fetch.zip"
}

# EventBridge rule - 6am EST daily (11:00 UTC)
resource "aws_cloudwatch_event_rule" "reddit_fetch_schedule" {
  name                = "cra-scam-reddit-daily-fetch"
  description         = "Trigger Reddit fetch daily at 6am EST"
  schedule_expression = "cron(0 11 * * ? *)"
}

# EventBridge target - Lambda
resource "aws_cloudwatch_event_target" "reddit_fetch_lambda" {
  rule      = aws_cloudwatch_event_rule.reddit_fetch_schedule.name
  target_id = "RedditFetchLambda"
  arn       = aws_lambda_function.reddit_fetch.arn
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "reddit_fetch_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reddit_fetch.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reddit_fetch_schedule.arn
}

# Outputs
output "reddit_fetch_lambda_arn" {
  description = "ARN of the Reddit fetch Lambda function"
  value       = aws_lambda_function.reddit_fetch.arn
}

output "reddit_fetch_schedule" {
  description = "Schedule for Reddit fetch (UTC)"
  value       = "Daily at 11:00 UTC (6:00 AM EST)"
}
