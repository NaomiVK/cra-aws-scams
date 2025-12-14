# EC2 Deployment Status

Last updated: 2025-12-13

## Current Status: PARTIALLY WORKING

- Frontend loads
- API starts successfully
- **ISSUE**: Frontend cannot connect to API (still calling localhost:3000 instead of /api)

---

## AWS Infrastructure (All Set Up)

### EC2 Instance
- **Region**: us-east-2 (Ohio)
- **Instance type**: t2.micro (free tier)
- **AMI**: Amazon Linux 2023
- **Instance ID**: i-0c4fac6440fd0b851
- **Public IP**: Changes on each start (currently 3.14.252.108)
- **Storage**: 20GB EBS

### Security Group: `cra-scam-sg`
- SSH (22) - My IP
- HTTP (80) - Anywhere
- HTTPS (443) - Anywhere

### Key Pair
- Name: `cra-scam-key`
- File: `cra-scam-key.pem` (in project root, gitignored)

### IAM Setup
- Created IAM admin user (not using root)
- Created IAM role: `cra-scam-ec2-role` with `AmazonSSMReadOnlyAccess`
- Role attached to EC2 instance

### AWS Parameter Store (Secrets)
- `/cra-scam/GOOGLE_MAPS_API_KEY` - SecureString ✅
- `/cra-scam/OPENAI_API_KEY` - SecureString ✅
- `/cra-scam/GSC_SERVICE_ACCOUNT` - SecureString (Google Search Console credentials JSON)

---

## Server Configuration (All Done)

### SSH Command
```bash
ssh -i "F:\vscode_projects\vs-code-projects\google_search\cra-aws-scams\cra-scam-key.pem" ec2-user@<PUBLIC_IP>
```

### Installed Software
- Node.js 22
- npm
- PM2 (process manager)
- nginx (reverse proxy)
- Git

### Swap Space (2GB)
Need to re-enable after each restart:
```bash
sudo swapon /swapfile
```

To make permanent (not done yet):
```bash
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### nginx Configuration
File: `/etc/nginx/conf.d/cra-scam.conf`
```nginx
server {
    listen 80;
    server_name _;

    root /home/ec2-user/cra-aws-scams/dist/apps/frontend/browser;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### PM2 Process
```bash
pm2 start dist/apps/api/main.js --name "cra-api"
pm2 save
```

---

## Files Uploaded to EC2

1. **Project code**: Cloned from GitHub

**Note**: `service-account-credentials.json` is NO LONGER needed on EC2. GSC credentials are now loaded from AWS Parameter Store.

---

## Adding GSC Credentials to AWS Parameter Store

The Google Search Console service account credentials must be stored in Parameter Store as a JSON string.

### Option 1: AWS Console (Recommended)

1. Go to **AWS Systems Manager** → **Parameter Store** → **Create parameter**
2. Settings:
   - **Name**: `/cra-scam/GSC_SERVICE_ACCOUNT`
   - **Type**: `SecureString`
   - **Value**: Paste the entire contents of `service-account-credentials.json`
3. Click **Create parameter**

### Option 2: AWS CLI

```bash
# From a machine with AWS CLI configured
aws ssm put-parameter \
  --name "/cra-scam/GSC_SERVICE_ACCOUNT" \
  --type "SecureString" \
  --value "$(cat service-account-credentials.json)" \
  --region us-east-2
```

### Verify the Parameter

```bash
# Check it exists (won't show decrypted value)
aws ssm get-parameter --name "/cra-scam/GSC_SERVICE_ACCOUNT" --region us-east-2

# To see the actual value (be careful with this)
aws ssm get-parameter --name "/cra-scam/GSC_SERVICE_ACCOUNT" --with-decryption --region us-east-2
```

---

## Current Issue: Frontend API Connection

### Problem
Frontend is calling `http://localhost:3000/api/...` instead of `/api/...`

Browser console errors:
```
GET http://localhost:3000/api/scams/dashboard net::ERR_CONNECTION_REFUSED
GET http://localhost:3000/api/scams/emerging net::ERR_CONNECTION_REFUSED
```

### What We Know
- API is running correctly on EC2 (PM2 status: online)
- API responds to `curl http://localhost:3000/api` on EC2
- nginx proxy config is correct
- `environment.prod.ts` has `apiUrl: '/api'` (correct)
- `environment.ts` has `apiUrl: 'http://localhost:3000/api'` (dev only)

### What We Tried
- `npx nx build frontend --configuration=production --verbose`
- `npx nx reset` + rebuild with `--skip-nx-cache`
- Deleting `dist/apps/frontend` and rebuilding

### Likely Causes
1. Build not picking up production config
2. Angular file replacement not working
3. Need to check `project.json` for frontend build configurations

### Things to Investigate
1. Check `apps/frontend/project.json` for build configuration
2. Verify Angular is doing file replacement for environment.prod.ts
3. Check if there's an `angular.json` or build config issue
4. Try building locally and checking the bundled environment

---

## Restart Checklist

When starting the EC2 instance after it's been stopped:

1. **Get new Public IP** from AWS Console

2. **SSH in**:
   ```bash
   ssh -i "path/to/cra-scam-key.pem" ec2-user@<NEW_IP>
   ```

3. **Enable swap**:
   ```bash
   sudo swapon /swapfile
   ```

4. **Start nginx** (should auto-start, but verify):
   ```bash
   sudo systemctl status nginx
   # If not running:
   sudo systemctl start nginx
   ```

5. **Start API**:
   ```bash
   cd ~/cra-aws-scams
   pm2 resurrect
   # Or if that doesn't work:
   pm2 start dist/apps/api/main.js --name "cra-api"
   ```

6. **Verify**:
   - `pm2 status` - should show cra-api online
   - `curl http://localhost:3000/api` - should return {"message":"Hello API"}
   - Visit `http://<NEW_IP>` in browser

---

## Useful Commands

### EC2 Server
```bash
# Check API status
pm2 status
pm2 logs cra-api --lines 50

# Restart API
pm2 restart cra-api

# Check nginx
sudo nginx -t
sudo systemctl reload nginx
sudo tail -20 /var/log/nginx/error.log

# Check disk/memory
df -h
free -h

# Rebuild app
cd ~/cra-aws-scams
git pull
npm install
npm run build
pm2 restart cra-api
```

### Local Machine
```bash
# SSH
ssh -i "cra-scam-key.pem" ec2-user@<IP>

# Upload file
scp -i "cra-scam-key.pem" <local-file> ec2-user@<IP>:~/cra-aws-scams/
```

---

## Cost Notes

- t2.micro: 750 free hours/month (first 12 months)
- 1 instance 24/7 = ~720 hours = FREE
- **Stop instance when not using it** to save hours
- EBS storage: 30GB free, using 20GB

---

## Code Changes Made for AWS

1. **Added AWS SDK**: `@aws-sdk/client-ssm`

2. **Created `aws-config.service.ts`**: Loads secrets from Parameter Store in production, from .env in development

3. **Updated `config.controller.ts`**: Uses AwsConfigService for Maps API key

4. **Updated `embedding.service.ts`**: Uses AwsConfigService for OpenAI key

5. **Updated `environment.prod.ts`**: Added missing config fields, CORS set to `*`

6. **Updated `main.ts`**: CORS handles `*` for production

---

## Next Steps to Fix

1. **Debug the Angular build configuration**
   - Check `apps/frontend/project.json` for fileReplacements
   - Ensure production build replaces environment.ts with environment.prod.ts

2. **Alternative: Hardcode API URL for testing**
   - Temporarily change `environment.ts` to use `/api` instead of localhost
   - Rebuild and test

3. **Check the built bundle**
   - After build, grep the JS files for "localhost" to see if it's still there:
   ```bash
   grep -r "localhost:3000" ~/cra-aws-scams/dist/apps/frontend/
   ```
