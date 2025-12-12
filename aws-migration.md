# AWS Migration Plan for CRA Scam Detection

This document outlines the plan to migrate the CRA Scam Detection dashboard to AWS, primarily for learning AWS while building a real project.

---

## Project Goal

Learn AWS by deploying this NestJS + Angular application to AWS infrastructure, using free tier where possible.

---

## Current Architecture (Local)

```
[Angular Frontend (port 4200)] → [NestJS API (port 3000)] → External APIs
                                         ↓
                                   - Google Search Console API
                                   - Google Trends API
                                   - OpenAI API
```

### Current Tech Stack
- **Frontend**: Angular 20 with Bootstrap/ng-bootstrap
- **Backend**: NestJS (Node.js framework)
- **Database**: None (uses in-memory `node-cache`)
- **External APIs**: Google Search Console, Google Trends, OpenAI

---

## Target AWS Architecture

```
[S3 + CloudFront] → Angular frontend (HTTPS)
        ↓
    [API Gateway] → [Lambda] → [DynamoDB (optional)]
                        ↓
                  External APIs (Search Console, Trends, OpenAI)
```

---

## Free Tier Compatibility Analysis

### What Works with Free Tier

| Service | Free Tier Limit | Fits Project? |
|---------|-----------------|---------------|
| **S3** | 5GB storage, 20k GET, 2k PUT | Yes |
| **CloudFront** | 1TB transfer, 10M requests | Yes |
| **API Gateway** | 1M HTTP API calls/month | Yes |
| **Lambda** | 1M requests, 400k GB-seconds | Yes (with adaptation) |
| **DynamoDB** | 25GB, 25 read/write units | Yes (if needed) |
| **Secrets Manager** | Some free, then $0.40/secret/month | Minimal cost |

### External API Costs (Not AWS)

| Service | Cost |
|---------|------|
| Google Search Console API | Free |
| Google Trends API | Free (web scraping) |
| **OpenAI API** | Pay-as-you-go (NOT free) |

---

## Key Challenges

### 1. NestJS is Not Lambda-Native

The `aws-getting-started.md` guide assumes a simple Lambda function. This project uses NestJS, a full framework that requires adaptation.

**Solution**: Use `@vendia/serverless-express` or `serverless-http` to wrap NestJS for Lambda.

```bash
npm install @vendia/serverless-express
```

### 2. Service Account Credentials

The app requires `service-account-credentials.json` for Google Search Console API.

**Solution**: Store in AWS Secrets Manager and load at runtime.

### 3. Environment Variables

Current `.env` file contains:
- `GOOGLE_MAPS_API_KEY`
- Other configuration

**Solution**: Use Lambda environment variables or Secrets Manager.

### 4. In-Memory Cache Won't Work

`node-cache` stores data in memory. Lambda instances are ephemeral.

**Solutions**:
- Use DynamoDB for persistent caching
- Use ElastiCache (not free tier)
- Accept cache misses on cold starts (simplest)

---

## Migration Steps

### Phase 1: Prepare the Codebase

- [ ] Add `@vendia/serverless-express` for Lambda compatibility
- [ ] Create `lambda.ts` entry point for serverless deployment
- [ ] Abstract credential loading to support Secrets Manager
- [ ] Update environment configuration for AWS
- [ ] Test locally with serverless-offline (optional)

### Phase 2: Set Up AWS Infrastructure

- [ ] Create S3 bucket for Angular frontend
- [ ] Set up CloudFront distribution
- [ ] Create Lambda function
- [ ] Configure API Gateway (HTTP API)
- [ ] Store credentials in Secrets Manager
- [ ] Set up IAM roles with proper permissions

### Phase 3: Deploy Backend

- [ ] Package NestJS app for Lambda
- [ ] Deploy to Lambda
- [ ] Configure API Gateway routes
- [ ] Test all endpoints
- [ ] Set up CloudWatch logging

### Phase 4: Deploy Frontend

- [ ] Update Angular environment with API Gateway URL
- [ ] Build Angular for production
- [ ] Upload to S3
- [ ] Configure CloudFront
- [ ] Test end-to-end

### Phase 5: Optional Enhancements

- [ ] Add DynamoDB for persistent storage/caching
- [ ] Set up custom domain (Route 53)
- [ ] Add CI/CD with GitHub Actions
- [ ] Configure CloudWatch alarms

---

## Files to Create/Modify

### New Files Needed

```
apps/api/src/lambda.ts          # Lambda entry point
apps/api/src/serverless.ts      # Serverless express adapter
serverless.yml                   # Serverless Framework config (optional)
buildspec.yml                    # AWS CodeBuild config (optional)
```

### Files to Modify

```
apps/api/src/main.ts            # Conditional bootstrap for Lambda vs local
apps/api/src/services/*.ts      # Update credential loading
apps/frontend/src/environments/ # Add production API URL
package.json                     # Add serverless dependencies
```

---

## Lambda Entry Point Example

```typescript
// apps/api/src/lambda.ts
import { configure as serverlessExpress } from '@vendia/serverless-express';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app/app.module';

let cachedServer;

export const handler = async (event, context) => {
  if (!cachedServer) {
    const app = await NestFactory.create(AppModule);
    app.enableCors();
    await app.init();
    cachedServer = serverlessExpress({ app: app.getHttpAdapter().getInstance() });
  }
  return cachedServer(event, context);
};
```

---

## Cost Estimate (Monthly)

| Service | Estimated Cost |
|---------|----------------|
| AWS (within free tier) | $0 |
| AWS Secrets Manager (1-2 secrets) | ~$0.80 |
| **OpenAI API** | Varies by usage ($5-50+) |
| **Total** | ~$1-50+ depending on OpenAI usage |

---

## Resources

- [AWS Free Tier](https://aws.amazon.com/free/)
- [Serverless NestJS](https://docs.nestjs.com/faq/serverless)
- [@vendia/serverless-express](https://github.com/vendia/serverless-express)
- [AWS Lambda + API Gateway](https://docs.aws.amazon.com/lambda/latest/dg/services-apigateway.html)

---

## Notes

- The original `aws-getting-started.md` is a learning guide for basic AWS concepts
- This project requires more work due to NestJS framework and external API dependencies
- OpenAI costs are unavoidable regardless of AWS setup
- Start with Phase 1-2 to learn the basics, then iterate
