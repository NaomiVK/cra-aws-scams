# AWS Getting Started: Node.js + Angular + DynamoDB (Free Tier)

A practical walkthrough to deploy your local app on AWS.

---

## What You'll Set Up

```
[S3 + CloudFront] → Angular frontend (HTTPS)
        ↓
    [API Gateway] → [Lambda] → [DynamoDB]
```

**Why this stack:**
- 100% free tier eligible
- No servers to manage
- Matches what your team uses (Lambda)

**Estimated time:** 1-2 hours

---

## Prerequisites

- AWS account created
- AWS CLI installed locally
- Your Node.js API + Angular app working locally

### Install AWS CLI

```bash
# macOS
brew install awscli

# Windows
choco install awscli

# Verify
aws --version
```

### Configure AWS CLI

```bash
aws configure
```

You'll need:
- Access Key ID
- Secret Access Key
- Region (e.g., `us-east-1`)

To get keys: **IAM Console** → **Users** → Your user → **Security credentials** → **Create access key**

---

## Step 1: Create DynamoDB Table

DynamoDB is AWS's NoSQL database—free tier gives you 25GB storage + 25 read/write units.

### 1.1 Create Table

1. Go to **DynamoDB Console** → **Create table**
2. Settings:
   - Table name: `items`
   - Partition key: `id` (String)
   - Leave sort key empty
   - Settings: **Default settings**
3. Click **Create table**

That's it—no clusters, no connection strings, no VPC config.

### 1.2 Test It (Optional)

1. Click your table → **Explore table items**
2. Click **Create item**
3. Add: `id` = "test-1", add attribute `name` = "Hello DynamoDB"
4. Click **Create item**

---

## Step 2: Create Lambda Function

### 2.1 Create the Function

1. Go to **Lambda Console** → **Create function**
2. Settings:
   - Function name: `dashboard-api`
   - Runtime: **Node.js 20.x**
   - Architecture: **arm64** (cheaper, faster)
   - Permissions: **Create a new role with basic Lambda permissions**
3. Click **Create function**

### 2.2 Add DynamoDB Permissions

1. In your Lambda function → **Configuration** tab → **Permissions**
2. Click the role name (opens IAM)
3. Click **Add permissions** → **Attach policies**
4. Search and add: `AmazonDynamoDBFullAccess`

### 2.3 Add Your Code

Replace the default code with:

```javascript
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand, PutCommand, GetCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = "items";

export const handler = async (event) => {
  const path = event.rawPath || event.path || "";
  const method = event.requestContext?.http?.method || event.httpMethod;
  
  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };

  try {
    // Health check
    if (path === "/health") {
      return { statusCode: 200, headers, body: JSON.stringify({ status: "healthy" }) };
    }

    // GET /api/items - List all items
    if (path === "/api/items" && method === "GET") {
      const result = await docClient.send(new ScanCommand({ TableName: TABLE_NAME }));
      return { statusCode: 200, headers, body: JSON.stringify(result.Items || []) };
    }

    // POST /api/items - Create item
    if (path === "/api/items" && method === "POST") {
      const body = JSON.parse(event.body || "{}");
      const item = {
        id: Date.now().toString(),
        name: body.name,
        createdAt: new Date().toISOString()
      };
      await docClient.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
      return { statusCode: 201, headers, body: JSON.stringify(item) };
    }

    // DELETE /api/items/:id
    if (path.startsWith("/api/items/") && method === "DELETE") {
      const id = path.split("/").pop();
      await docClient.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { id } }));
      return { statusCode: 204, headers, body: "" };
    }

    // OPTIONS (CORS preflight)
    if (method === "OPTIONS") {
      return { statusCode: 200, headers, body: "" };
    }

    return { statusCode: 404, headers, body: JSON.stringify({ error: "Not found" }) };

  } catch (error) {
    console.error(error);
    return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
  }
};
```

Click **Deploy** to save.

---

## Step 3: Create API Gateway

This gives your Lambda a public URL.

### 3.1 Create HTTP API

1. Go to **API Gateway Console** → **Create API**
2. Choose **HTTP API** → **Build**
3. Add integration:
   - Integration type: **Lambda**
   - Lambda function: `dashboard-api`
4. API name: `dashboard-api`
5. Click **Next**

### 3.2 Configure Routes

Add these routes:

| Method | Path |
|--------|------|
| GET | /health |
| GET | /api/items |
| POST | /api/items |
| DELETE | /api/items/{id} |
| OPTIONS | /{proxy+} |

6. Click **Next** → Leave stage as `$default` → **Create**

### 3.3 Get Your API URL

After creation, you'll see an **Invoke URL** like:
```
https://abc123xyz.execute-api.us-east-1.amazonaws.com
```

### 3.4 Test It

```bash
# Health check
curl https://YOUR-API-URL/health

# Create item
curl -X POST https://YOUR-API-URL/api/items \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Item"}'

# List items
curl https://YOUR-API-URL/api/items
```

---

## Step 4: Deploy Angular Frontend

### 4.1 Update Angular Environment

In your Angular app, update the API URL:

```typescript
// src/environments/environment.prod.ts
export const environment = {
  production: true,
  apiUrl: 'https://YOUR-API-URL'
};
```

### 4.2 Build Angular

```bash
ng build --configuration=production
# Output: dist/your-app-name/browser/
```

### 4.3 Create S3 Bucket

1. Go to **S3 Console** → **Create bucket**
2. Settings:
   - Bucket name: `dashboard-frontend-YOUR-UNIQUE-ID` (must be globally unique)
   - Region: Same as your Lambda
   - **Uncheck** "Block all public access" (we need public access for now)
   - Acknowledge the warning
3. Click **Create bucket**

### 4.4 Enable Static Website Hosting

1. Click your bucket → **Properties** tab
2. Scroll to **Static website hosting** → **Edit**
3. Enable, set:
   - Index document: `index.html`
   - Error document: `index.html` (for Angular routing)
4. Save → Note the **Bucket website endpoint**

### 4.5 Add Bucket Policy

1. **Permissions** tab → **Bucket policy** → **Edit**
2. Add this policy (replace YOUR-BUCKET-NAME):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::YOUR-BUCKET-NAME/*"
    }
  ]
}
```

### 4.6 Upload Angular Build

```bash
aws s3 sync dist/your-app-name/browser/ s3://YOUR-BUCKET-NAME/
```

### 4.7 Test

Open your S3 website endpoint in a browser:
```
http://YOUR-BUCKET-NAME.s3-website-us-east-1.amazonaws.com
```

---

## Step 5: Add CloudFront (HTTPS)

S3 website hosting is HTTP only. CloudFront adds HTTPS + caching.

### 5.1 Create Distribution

1. Go to **CloudFront Console** → **Create distribution**
2. Origin settings:
   - Origin domain: Select your S3 bucket (the one ending in `.s3.amazonaws.com`)
   - Origin access: **Origin access control settings (recommended)**
   - Click **Create new OAC** → Create
3. Default cache behavior:
   - Viewer protocol policy: **Redirect HTTP to HTTPS**
4. Settings:
   - Default root object: `index.html`
5. Click **Create distribution**

### 5.2 Update S3 Bucket Policy

CloudFront will show a banner to update your bucket policy. Click **Copy policy**, then:

1. Go to your S3 bucket → **Permissions** → **Bucket policy**
2. Replace with the new policy CloudFront provided

### 5.3 Handle Angular Routing

1. In CloudFront → Your distribution → **Error pages**
2. Click **Create custom error response**:
   - HTTP error code: `403`
   - Customize error response: Yes
   - Response page path: `/index.html`
   - HTTP response code: `200`
3. Repeat for error code `404`

### 5.4 Wait for Deployment

CloudFront takes ~5-10 minutes to deploy. Status will change from "Deploying" to a date.

Your app is now live at:
```
https://d1234abcdef.cloudfront.net
```

---

## Step 6: Clean Up (Optional)

If you want to tear everything down:

```bash
# Empty S3 bucket first
aws s3 rm s3://YOUR-BUCKET-NAME --recursive

# Then delete via console:
# - CloudFront distribution (disable first, wait, then delete)
# - S3 bucket
# - API Gateway
# - Lambda function
# - DynamoDB table
# - IAM role (created by Lambda)
```

---

## Quick Reference

| Service | Free Tier |
|---------|-----------|
| Lambda | 1M requests/month, 400k GB-seconds |
| API Gateway | 1M HTTP API calls/month |
| DynamoDB | 25GB storage, 25 read/write capacity units |
| S3 | 5GB storage, 20k GET, 2k PUT |
| CloudFront | 1TB transfer, 10M requests |

### Useful Commands

```bash
# Upload Angular build
aws s3 sync dist/app/browser/ s3://BUCKET --delete

# Invalidate CloudFront cache after deploy
aws cloudfront create-invalidation --distribution-id DIST-ID --paths "/*"

# View Lambda logs
aws logs tail /aws/lambda/dashboard-api --follow

# List DynamoDB items
aws dynamodb scan --table-name items
```

### Update Your Angular App

```bash
# Build
ng build --configuration=production

# Deploy
aws s3 sync dist/your-app/browser/ s3://YOUR-BUCKET --delete

# Invalidate cache
aws cloudfront create-invalidation --distribution-id YOUR-DIST-ID --paths "/*"
```

---

## Next Steps

Once comfortable with this setup:

1. **Custom domain** — Route 53 + ACM certificate
2. **CI/CD** — GitHub Actions to auto-deploy on push
3. **Monitoring** — CloudWatch dashboards and alarms
4. **Authentication** — Cognito for user login

---

## Troubleshooting

**Lambda 500 errors:**
- Check CloudWatch logs: Lambda → Monitor → View CloudWatch logs

**CORS errors in browser:**
- Verify Lambda returns proper CORS headers
- Check API Gateway has OPTIONS route

**Angular routes return 403/404:**
- Verify CloudFront custom error responses are set

**S3 access denied:**
- Check bucket policy is correct
- Verify "Block public access" is off (for direct S3 hosting)

**CloudFront still showing old content:**
- Create invalidation: `aws cloudfront create-invalidation --distribution-id ID --paths "/*"`
