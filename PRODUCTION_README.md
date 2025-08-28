# AWS Security Monitor - Production Deployment Guide

## 🚀 Complete Production Deployment on Ubuntu Server

This guide will help you deploy the AWS Security Monitor to a production Ubuntu server with automated daily reports.

## 📋 Deployment Steps

### 1. Upload Files to Server

Transfer these files to your Ubuntu server:
```bash
# On your local machine
scp -r aws-security-monitor/ user@your-server-ip:/tmp/

# On the server
sudo mv /tmp/aws-security-monitor /opt/
```

### 2. Run Deployment Script

```bash
cd /opt/aws-security-monitor
sudo chmod +x deploy.sh
sudo ./deploy.sh
```

This script will:
- ✅ Install Python 3, pip, and required packages
- ✅ Create dedicated `aws-monitor` user
- ✅ Set up directory structure in `/opt/aws-security-monitor`
- ✅ Create Python virtual environment
- ✅ Install dependencies
- ✅ Create production configuration
- ✅ Set up systemd service

### 3. Configure AWS Credentials

```bash
# Copy your AWS credentials
sudo mkdir -p /home/aws-monitor/.aws
sudo cp ~/.aws/credentials /home/aws-monitor/.aws/
sudo cp ~/.aws/config /home/aws-monitor/.aws/
sudo chown -R aws-monitor:aws-monitor /home/aws-monitor/.aws/
sudo chmod 600 /home/aws-monitor/.aws/*
```

### 4. Set Up Cron Job

```bash
sudo chmod +x setup_cron_production.sh
sudo ./setup_cron_production.sh
```

This will:
- ✅ Prompt for destination and sender email addresses
- ✅ Set up daily cron job for 8:00 PM IST
- ✅ Configure log rotation
- ✅ Set server timezone to IST
- ✅ Create health check script

### 5. Test the Installation

```bash
# Test manual run
sudo -u aws-monitor /opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/run_monitor.py

# Check if email was sent
tail -f /var/log/aws-security-monitor/daily_report.log
```

## 📁 Directory Structure

```
/opt/aws-security-monitor/
├── aws_security_monitor.py      # Main monitoring script
├── run_monitor.py               # Production wrapper (24-hour reports)
├── requirements.txt             # Dependencies
├── config.py                   # Production configuration
├── venv/                       # Python virtual environment
└── check_cron_health.sh        # Health monitoring

/var/log/aws-security-monitor/
├── daily_report.log            # Daily execution logs
└── cron.log                    # Cron job logs

/var/lib/aws-security-monitor/
├── last_successful_run         # Health check timestamp
└── processed_events.pkl        # (Not used in daily mode)

/home/aws-monitor/.aws/
├── credentials                 # AWS credentials
└── config                     # AWS CLI config
```

## ⚙️ Configuration

### Email Settings (in config.py)
```python
SES_FROM_EMAIL = "no-reply@bamko.net"
SES_TO_EMAIL = "your-email@domain.com"
SES_REGION = "us-east-1"
SES_PROFILE = "unified"
```

### Monitoring Settings
- **Schedule**: Daily at 8:00 PM IST (20:00)
- **Lookback**: Last 24 hours of activity
- **Profiles**: Both 'default' and 'unified'
- **Regions**: Major AWS regions

## 🔧 Management Commands

### View Cron Jobs
```bash
sudo -u aws-monitor crontab -l
```

### Manual Test Run
```bash
sudo -u aws-monitor /opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/run_monitor.py
```

### Check Logs
```bash
# Daily execution logs
tail -f /var/log/aws-security-monitor/daily_report.log

# Cron job logs
tail -f /var/log/aws-security-monitor/cron.log

# System logs
journalctl -u aws-security-monitor -f
```

### Health Check
```bash
/opt/aws-security-monitor/check_cron_health.sh
```

### Restart/Stop Cron
```bash
# Disable cron job
sudo -u aws-monitor crontab -r

# Re-run setup
sudo ./setup_cron_production.sh
```

## 🎯 Daily Report Features

### What's Different from Real-time Mode:
- **24-hour lookback** instead of 10 minutes
- **Daily summary** at 8 PM IST
- **No duplicate filtering** (shows all activity in last 24 hours)
- **Enhanced logging** for production troubleshooting

### Report Contents:
- ✅ All security-relevant changes in last 24 hours
- ✅ Multi-account and multi-region coverage
- ✅ Executive-friendly HTML formatting
- ✅ Detailed event information with user attribution
- ✅ Clean presentation without debug noise

## 🛠️ Troubleshooting

### Common Issues:

**1. No emails received:**
```bash
# Check SES permissions
aws ses get-send-quota --profile unified

# Verify email addresses
aws ses list-verified-email-addresses --profile unified

# Check logs
tail -f /var/log/aws-security-monitor/daily_report.log
```

**2. Cron not running:**
```bash
# Check cron service
sudo systemctl status cron

# Check user crontab
sudo -u aws-monitor crontab -l

# Check cron logs
grep aws-monitor /var/log/syslog
```

**3. Permission errors:**
```bash
# Fix ownership
sudo chown -R aws-monitor:aws-monitor /opt/aws-security-monitor
sudo chown -R aws-monitor:aws-monitor /var/log/aws-security-monitor
sudo chown -R aws-monitor:aws-monitor /var/lib/aws-security-monitor
```

**4. AWS credentials issues:**
```bash
# Test AWS access
sudo -u aws-monitor aws sts get-caller-identity --profile unified
```

## 📊 Monitoring & Alerts

### Health Monitoring:
- **Health check script** monitors last successful run
- **Log rotation** keeps logs manageable (30 days retention)
- **Systemd integration** for better process management

### Success Indicators:
- ✅ Daily log entries in `/var/log/aws-security-monitor/daily_report.log`
- ✅ Email notifications received at configured address
- ✅ Health check script returns success
- ✅ No error entries in system logs

## 🔒 Security Best Practices

1. **Dedicated user**: Runs as `aws-monitor` (not root)
2. **Minimal permissions**: Only SES and CloudTrail access needed
3. **Credential isolation**: AWS credentials in dedicated directory
4. **Log security**: Proper file permissions on logs and configs
5. **Network security**: Consider firewall rules for outbound SES

## 🚀 You're Ready!

Once deployed, your AWS Security Monitor will:
- 📧 Send daily security reports at 8 PM IST
- 🔍 Monitor all configured AWS accounts and regions
- 📊 Provide executive-ready security insights
- ⚡ Alert on critical infrastructure changes
- 🛡️ Help maintain security posture across your AWS environment

The system is now production-ready and will automatically monitor your AWS infrastructure daily!