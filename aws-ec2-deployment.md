# AWS EC2 Deployment Guide for CRA Scam Detection

A beginner-friendly guide to deploying this NestJS + Angular app on AWS EC2.

---

## Prerequisites

- AWS account (root access is fine for learning)
- Your local project working (`npm start` runs successfully)
- Git repository (GitHub, GitLab, etc.) with your code

---

## Overview: What We're Building

```
[Your Computer] → [GitHub] → [EC2 Instance] → [Internet Users]
                                   │
                              ┌────┴────┐
                              │ nginx   │ (reverse proxy, port 80/443)
                              │ NestJS  │ (API, port 3000)
                              │ Angular │ (static files)
                              └─────────┘
```

---

## Part 1: AWS Console Setup (One-Time)

### Step 1.1: Create an IAM User (Don't Use Root!)

> **Why?** Root account has unlimited power. Create a limited admin user for safety.

1. Go to AWS Console → Search "IAM" → Click **IAM**
2. Left sidebar → **Users** → **Create user**
3. User name: `admin-yourname`
4. Check ✅ **Provide user access to the AWS Management Console**
5. Select **I want to create an IAM user**
6. Set a password
7. Click **Next**
8. Select **Attach policies directly**
9. Search and check ✅ **AdministratorAccess**
10. Click **Next** → **Create user**
11. **Save the sign-in URL** (looks like `https://123456789.signin.aws.amazon.com/console`)
12. **Log out of root** and log in as your new IAM user

---

### Step 1.2: Choose a Region

AWS has data centers worldwide. Pick one close to your users.

1. Top-right corner of AWS Console → Click region dropdown
2. Select a region (e.g., **US East (N. Virginia) us-east-1** or **Canada (Central) ca-central-1**)
3. **Stick with this region** for everything

---

### Step 1.3: Create a Key Pair (For SSH Access)

> **Why?** This is how you'll securely connect to your server.

1. Search "EC2" → Click **EC2**
2. Left sidebar → **Network & Security** → **Key Pairs**
3. Click **Create key pair**
4. Name: `cra-scam-detection-key`
5. Key pair type: **RSA**
6. Private key format: **.pem** (for Mac/Linux) or **.ppk** (for Windows with PuTTY)
7. Click **Create key pair**
8. **A file downloads automatically - SAVE THIS FILE SECURELY!**
   - You cannot download it again
   - Store it in a safe location (e.g., `~/.ssh/` on Mac/Linux)

---

### Step 1.4: Create a Security Group (Firewall Rules)

> **Why?** Controls what traffic can reach your server.

1. In EC2 → Left sidebar → **Network & Security** → **Security Groups**
2. Click **Create security group**
3. Fill in:
   - Name: `cra-scam-detection-sg`
   - Description: `Security group for CRA Scam Detection app`
   - VPC: Leave default
4. **Inbound rules** → Click **Add rule** for each:

   | Type | Port | Source | Description |
   |------|------|--------|-------------|
   | SSH | 22 | My IP | SSH access (auto-fills your IP) |
   | HTTP | 80 | Anywhere (0.0.0.0/0) | Web traffic |
   | HTTPS | 443 | Anywhere (0.0.0.0/0) | Secure web traffic |
   | Custom TCP | 3000 | Anywhere (0.0.0.0/0) | NestJS API (temporary, for testing) |
   | Custom TCP | 4200 | Anywhere (0.0.0.0/0) | Angular dev (temporary, for testing) |

5. **Outbound rules**: Leave default (all traffic allowed out)
6. Click **Create security group**

---

## Part 2: Launch EC2 Instance

### Step 2.1: Launch Instance

1. EC2 Dashboard → Click **Launch instance**
2. **Name**: `cra-scam-detection`
3. **Application and OS Images (AMI)**:
   - Select **Amazon Linux 2023** (free tier eligible)
   - Or **Ubuntu Server 22.04 LTS** (also free tier)
4. **Instance type**:
   - `t2.micro` (free tier) - 1 vCPU, 1 GB RAM
   - Or `t3.micro` (free tier in some regions)
   - Note: 1GB RAM is tight for NestJS + Angular build. Consider `t3.small` if you have issues.
5. **Key pair**: Select `cra-scam-detection-key` (created earlier)
6. **Network settings**:
   - Click **Edit**
   - **Auto-assign public IP**: Enable
   - **Firewall**: Select existing security group → `cra-scam-detection-sg`
7. **Configure storage**:
   - 20 GB gp3 (free tier allows up to 30 GB)
8. Click **Launch instance**

### Step 2.2: Wait and Get IP Address

1. Click **View all instances**
2. Wait for **Instance state** to show **Running** (1-2 minutes)
3. Click on your instance
4. Copy the **Public IPv4 address** (e.g., `54.123.45.67`)

---

## Part 3: Connect to Your Server

### Option A: Mac/Linux Terminal

```bash
# Set correct permissions on key file (required)
chmod 400 ~/path/to/cra-scam-detection-key.pem

# Connect (Amazon Linux)
ssh -i ~/path/to/cra-scam-detection-key.pem ec2-user@YOUR_PUBLIC_IP

# Connect (Ubuntu)
ssh -i ~/path/to/cra-scam-detection-key.pem ubuntu@YOUR_PUBLIC_IP
```

### Option B: Windows (PowerShell/WSL)

```powershell
# PowerShell - connect to Amazon Linux
ssh -i C:\path\to\cra-scam-detection-key.pem ec2-user@YOUR_PUBLIC_IP
```

### Option C: Windows (PuTTY)

1. Open PuTTY
2. Host Name: `ec2-user@YOUR_PUBLIC_IP`
3. Connection → SSH → Auth → Credentials → Browse for `.ppk` file
4. Click Open

---

## Part 4: Server Setup (Run These Commands)

Once connected via SSH, run these commands:

### Step 4.1: Update System

```bash
# Amazon Linux 2023
sudo dnf update -y

# Ubuntu
sudo apt update && sudo apt upgrade -y
```

### Step 4.2: Install Node.js 20

```bash
# Amazon Linux 2023
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo dnf install -y nodejs

# Ubuntu
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

Verify:
```bash
node --version  # Should show v20.x.x
npm --version   # Should show 10.x.x
```

### Step 4.3: Install Git

```bash
# Amazon Linux
sudo dnf install -y git

# Ubuntu
sudo apt install -y git
```

### Step 4.4: Install PM2 (Process Manager)

> **Why?** Keeps your app running after you disconnect, auto-restarts on crash.

```bash
sudo npm install -g pm2
```

### Step 4.5: Install nginx (Reverse Proxy)

> **Why?** Serves your Angular app and proxies API requests to NestJS.

```bash
# Amazon Linux
sudo dnf install -y nginx

# Ubuntu
sudo apt install -y nginx
```

Start nginx:
```bash
sudo systemctl start nginx
sudo systemctl enable nginx  # Start on boot
```

Test: Visit `http://YOUR_PUBLIC_IP` in browser - should see nginx welcome page.

---

## Part 5: Deploy Your Application

### Step 5.1: Clone Your Repository

```bash
cd ~
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git cra-scam-detection
cd cra-scam-detection
```

### Step 5.2: Upload Credentials File

You need to get `service-account-credentials.json` onto the server.

**Option A: SCP from your local machine** (run locally, not on server)
```bash
scp -i ~/path/to/key.pem ./service-account-credentials.json ec2-user@YOUR_IP:~/cra-scam-detection/
```

**Option B: Create file manually on server**
```bash
nano ~/cra-scam-detection/service-account-credentials.json
# Paste contents, Ctrl+X, Y, Enter to save
```

### Step 5.3: Create Environment File

```bash
cd ~/cra-scam-detection
nano .env
```

Add your environment variables:
```
GOOGLE_MAPS_API_KEY=your_google_maps_api_key_here
```

### Step 5.4: Install Dependencies

```bash
npm install
```

> **Note:** If you get memory errors on t2.micro, create a swap file:
> ```bash
> sudo fallocate -l 2G /swapfile
> sudo chmod 600 /swapfile
> sudo mkswap /swapfile
> sudo swapon /swapfile
> ```

### Step 5.5: Build the Application

```bash
# Build both API and frontend
npm run build
```

This creates:
- `dist/apps/api/` - NestJS compiled code
- `dist/apps/frontend/browser/` - Angular static files

---

## Part 6: Configure nginx

### Step 6.1: Create nginx Configuration

```bash
sudo nano /etc/nginx/conf.d/cra-scam-detection.conf
```

Paste this configuration:

```nginx
server {
    listen 80;
    server_name _;  # Accepts any hostname (or use your domain)

    # Serve Angular static files
    root /home/ec2-user/cra-scam-detection/dist/apps/frontend/browser;
    index index.html;

    # Angular routes - serve index.html for all frontend routes
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy API requests to NestJS
    location /api {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

> **For Ubuntu**: Change `/home/ec2-user/` to `/home/ubuntu/`

### Step 6.2: Test and Reload nginx

```bash
# Test configuration syntax
sudo nginx -t

# If OK, reload
sudo systemctl reload nginx
```

### Step 6.3: Fix Permissions (if needed)

```bash
# Allow nginx to read your files
chmod 755 /home/ec2-user
chmod -R 755 /home/ec2-user/cra-scam-detection/dist
```

---

## Part 7: Start the API with PM2

### Step 7.1: Start the NestJS API

```bash
cd ~/cra-scam-detection

# Start the API
pm2 start dist/apps/api/main.js --name "cra-api"

# Save PM2 process list (survives reboot)
pm2 save

# Set PM2 to start on boot
pm2 startup
# Run the command it outputs (starts with sudo)
```

### Step 7.2: Useful PM2 Commands

```bash
pm2 status          # See running processes
pm2 logs cra-api    # View logs
pm2 restart cra-api # Restart API
pm2 stop cra-api    # Stop API
pm2 monit           # Real-time monitoring
```

---

## Part 8: Test Your Deployment

1. **Visit your app**: `http://YOUR_PUBLIC_IP`
2. **Test API directly**: `http://YOUR_PUBLIC_IP/api`
3. **Check logs if issues**: `pm2 logs cra-api`

---

## Part 9: Code Changes Needed

Only minimal changes required:

### 9.1: Update Frontend Production Environment

`apps/frontend/src/environments/environment.prod.ts`:
```typescript
export const environment = {
  production: true,
  apiUrl: '/api',  // This works with nginx proxy
};
```

### 9.2: Update API Production Environment

Create `apps/api/src/environments/environment.prod.ts`:
```typescript
export const environment = {
  production: true,
  port: 3000,

  google: {
    credentialsPath: '../../service-account-credentials.json',
    siteUrl: 'https://www.canada.ca/',
    craUrlFilters: [
      '/en/revenue-agency/',
      '/fr/agence-revenu/',
      '/en/services/taxes/',
      '/fr/services/impots/',
    ],
  },

  searchConsole: {
    maxRows: 5000,
    minImpressions: 100,
    maxDateRangeDays: 90,
  },

  scamDetection: {
    impressionThreshold: 500,
    defaultDateRangeDays: 28,
  },

  embedding: {
    similarityThreshold: 0.80,
    model: 'text-embedding-3-large',
  },

  cache: {
    analyticsTtl: 3600,
    trendsTtl: 1800,
    keywordsTtl: 300,
    embeddingsTtl: 86400,
    benchmarksTtl: 3600,
  },

  // In production, allow requests from any origin (nginx handles it)
  // Or set to your domain
  frontendUrl: '*',
};
```

### 9.3: Update API main.ts for Production CORS

`apps/api/src/main.ts` - the CORS config should handle production:
```typescript
app.enableCors({
  origin: environment.production ? true : environment.frontendUrl,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
});
```

---

## Part 10: Optional Enhancements

### 10.1: Add HTTPS with Let's Encrypt (Free SSL)

Requires a domain name pointing to your EC2 IP.

```bash
# Install certbot
sudo dnf install -y certbot python3-certbot-nginx  # Amazon Linux
sudo apt install -y certbot python3-certbot-nginx  # Ubuntu

# Get certificate (replace with your domain)
sudo certbot --nginx -d yourdomain.com

# Auto-renewal is set up automatically
```

### 10.2: Set Up a Domain Name

1. Buy domain from Route 53, Namecheap, GoDaddy, etc.
2. Create an A record pointing to your EC2 public IP
3. Update nginx `server_name` to your domain
4. Set up HTTPS with certbot

### 10.3: Elastic IP (Static IP)

EC2 public IPs change when you stop/start the instance.

1. EC2 → Elastic IPs → Allocate Elastic IP address
2. Actions → Associate Elastic IP address
3. Select your instance
4. Now your IP is permanent (free while instance is running)

---

## Part 11: Maintenance Commands

### Update Your App

```bash
cd ~/cra-scam-detection
git pull
npm install
npm run build
pm2 restart cra-api
```

### View Logs

```bash
pm2 logs cra-api         # API logs
sudo tail -f /var/log/nginx/error.log  # nginx errors
```

### Monitor Resources

```bash
htop                     # CPU/memory (install: sudo dnf/apt install htop)
df -h                    # Disk space
pm2 monit               # PM2 dashboard
```

---

## Cost Summary

| Resource | Free Tier | After Free Tier |
|----------|-----------|-----------------|
| EC2 t2.micro | 750 hrs/month for 12 months | ~$8-10/month |
| EBS Storage (20GB) | 30GB free for 12 months | ~$2/month |
| Data Transfer | 100GB out free | $0.09/GB |
| Elastic IP | Free while attached | $0.005/hr if unused |

**Total during free tier: $0/month**
**After free tier: ~$10-15/month**

---

## Troubleshooting

### "Permission denied" on SSH
```bash
chmod 400 your-key.pem
```

### nginx shows 502 Bad Gateway
- API not running: `pm2 status` then `pm2 start`
- Wrong port: Check nginx config points to port 3000

### App crashes on build (out of memory)
- Create swap file (see Step 5.4)
- Or upgrade to t3.small

### Can't connect to EC2
- Check security group has your IP for SSH
- Check instance is running
- Try EC2 Instance Connect (AWS Console → Connect button)

### API can't read credentials file
- Check file exists: `ls -la ~/cra-scam-detection/service-account-credentials.json`
- Check permissions: `chmod 600 service-account-credentials.json`

---

## Next Steps After Basic Deployment

1. **Security**: Remove ports 3000/4200 from security group (nginx handles everything on 80/443)
2. **Monitoring**: Set up CloudWatch alarms for CPU/memory
3. **Backups**: Create AMI snapshots periodically
4. **CI/CD**: Set up GitHub Actions to auto-deploy on push
