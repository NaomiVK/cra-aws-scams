# Useful Commands Reference

## Local Development

```bash
# Start both API and frontend
npm start

# Start individually
npm run start:api        # API on port 3000
npm run start:frontend   # Frontend on port 4200

# Build
npm run build            # Build everything
npm run build:api
npm run build:frontend

# Lint & Test
npm run lint
npm run test
```

---

## SSH into EC2

```bash
# Windows (Git Bash or PowerShell)
ssh -i "F:\vscode_projects\vs-code-projects\google_search\cra-aws-scams\cra-scam-key.pem" ec2-user@<PUBLIC_IP>

# Example with actual IP
ssh -i "F:\vscode_projects\vs-code-projects\google_search\cra-aws-scams\cra-scam-key.pem" ec2-user@3.14.252.108
```

---

## EC2 Server Commands

### Swap (run after each instance start)
```bash
sudo swapon /swapfile    # Enable swap
free -h                  # Verify swap is active
```

### PM2 (Process Manager)
```bash
pm2 status               # Check if API is running
pm2 logs cra-api         # View logs (live)
pm2 logs cra-api --lines 50   # Last 50 lines
pm2 restart cra-api      # Restart the API
pm2 stop cra-api         # Stop the API
pm2 start dist/apps/api/main.js --name "cra-api"  # Start fresh
pm2 save                 # Save process list for resurrect
pm2 resurrect            # Restore saved processes after reboot
```

### Nginx
```bash
sudo systemctl status nginx    # Check status
sudo systemctl start nginx     # Start
sudo systemctl restart nginx   # Restart
sudo systemctl reload nginx    # Reload config without restart
sudo nginx -t                  # Test config syntax
sudo tail -20 /var/log/nginx/error.log    # View error logs
sudo tail -20 /var/log/nginx/access.log   # View access logs
```

### System
```bash
df -h                    # Disk usage
free -h                  # Memory usage
top                      # Live process monitor (q to quit)
htop                     # Better process monitor (if installed)
```

---

## Deploy to EC2

### Full deployment from local machine:

```bash
# 1. Push to GitHub (local)
git add -A && git commit -m "Your message" && git push

# 2. SSH in
ssh -i "F:\vscode_projects\vs-code-projects\google_search\cra-aws-scams\cra-scam-key.pem" ec2-user@<PUBLIC_IP>

# 3. On EC2:
cd ~/cra-aws-scams
sudo swapon /swapfile
git pull
npm install
npm run build
pm2 restart cra-api
```

### If git pull fails (divergent branches):
```bash
git fetch origin
git reset --hard origin/main
npm install
npm run build
pm2 restart cra-api
```

---

## AWS CLI Commands

### Parameter Store (Secrets)
```bash
# List all parameters
aws ssm describe-parameters --region us-east-2

# Get parameter (without decryption)
aws ssm get-parameter --name "/cra-scam/GSC_SERVICE_ACCOUNT" --region us-east-2

# Get parameter (with decryption - shows actual value)
aws ssm get-parameter --name "/cra-scam/GSC_SERVICE_ACCOUNT" --with-decryption --region us-east-2

# Create/update parameter
aws ssm put-parameter \
  --name "/cra-scam/GSC_SERVICE_ACCOUNT" \
  --type "SecureString" \
  --value "$(cat service-account-credentials.json)" \
  --region us-east-2

# Update existing parameter (add --overwrite)
aws ssm put-parameter \
  --name "/cra-scam/GSC_SERVICE_ACCOUNT" \
  --type "SecureString" \
  --value "$(cat service-account-credentials.json)" \
  --region us-east-2 \
  --overwrite
```

---

## SCP File Transfer

```bash
# Upload file to EC2
scp -i "F:\vscode_projects\vs-code-projects\google_search\cra-aws-scams\cra-scam-key.pem" <LOCAL_FILE> ec2-user@<PUBLIC_IP>:~/cra-aws-scams/

# Download file from EC2
scp -i "F:\vscode_projects\vs-code-projects\google_search\cra-aws-scams\cra-scam-key.pem" ec2-user@<PUBLIC_IP>:~/cra-aws-scams/<REMOTE_FILE> .

# Examples
scp -i "cra-scam-key.pem" .env ec2-user@3.14.252.108:~/cra-aws-scams/
scp -i "cra-scam-key.pem" ec2-user@3.14.252.108:~/cra-aws-scams/pm2.log ./downloaded-pm2.log
```

---

## Debugging

### Test API locally on EC2
```bash
curl http://localhost:3000/api                    # Basic health check
curl http://localhost:3000/api/scams/dashboard    # Dashboard endpoint
curl http://localhost:3000/api/config/maps-key    # Check if Maps key loaded
```

### Check what's using a port
```bash
sudo lsof -i :3000    # What's on port 3000
sudo lsof -i :80      # What's on port 80
```

### Kill stuck processes
```bash
pkill -f node         # Kill all node processes
pm2 kill              # Kill PM2 daemon
```

---

## Git Commands

```bash
# Check status
git status
git log --oneline -5

# Discard all local changes
git checkout -- .
git clean -fd

# Reset to match remote exactly
git fetch origin
git reset --hard origin/main

# Stash changes temporarily
git stash
git stash pop
```

---

## Quick Reference

| Task | Command |
|------|---------|
| SSH in | `ssh -i "cra-scam-key.pem" ec2-user@<IP>` |
| Enable swap | `sudo swapon /swapfile` |
| Check API status | `pm2 status` |
| View API logs | `pm2 logs cra-api` |
| Restart API | `pm2 restart cra-api` |
| Pull & rebuild | `git pull && npm install && npm run build` |
| Check memory | `free -h` |
| Check disk | `df -h` |
