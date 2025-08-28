# Standard Operating Procedure (SOP)
# AWS Security Monitor - Real-time Change Detection System

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation Guide](#installation-guide)
5. [Configuration](#configuration)
6. [Testing & Validation](#testing--validation)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [Maintenance](#maintenance)
9. [Security Considerations](#security-considerations)
10. [Appendix](#appendix)

---

## Overview

### Purpose
The AWS Security Monitor is an automated security monitoring system that detects and alerts on infrastructure changes across multiple AWS accounts in real-time. It provides CloudTrail-level detail about what changed, who changed it, and the exact modifications made.

### Key Features
- **Multi-Account Monitoring**: Monitors all AWS profiles configured in ~/.aws/credentials
- **Real-time Detection**: Runs every 5 minutes to detect changes within 10-minute windows
- **Intelligent Filtering**: Excludes system-generated events (AWS service roles, automated backups)
- **Detailed Change Tracking**: Shows exactly what was added, removed, or modified
- **Executive-Friendly Alerts**: HTML-formatted emails with severity levels and categorization
- **Duplicate Prevention**: State management to avoid sending duplicate alerts

### What Gets Monitored
- **Security Groups**: Rule additions/removals with ports, protocols, and IPs
- **EC2 Instances**: Launch, termination, modifications with instance names
- **IAM**: User, role, and policy changes
- **S3**: Bucket policies and ACL modifications
- **RDS**: Database instance changes
- **Lambda**: Function code and configuration updates
- **SSM Sessions**: Remote access tracking
- **200+ Critical AWS API Calls**

---

## Architecture

### System Components
```
┌─────────────────────────────────────────────────────────┐
│                   Production Server                       │
│                                                          │
│  ┌──────────────┐      ┌─────────────────────────┐     │
│  │     Cron     │──────▶│  aws_security_monitor.py │    │
│  │  (*/5 * * *)│      │                           │     │
│  └──────────────┘      └───────────┬──────────────┘     │
│                                    │                     │
│                          ┌─────────▼──────────┐         │
│                          │   CloudTrail API    │         │
│                          │   (All Regions)     │         │
│                          └─────────┬──────────┘         │
│                                    │                     │
│                          ┌─────────▼──────────┐         │
│                          │   Process Events    │         │
│                          │  - Filter System    │         │
│                          │  - Extract Changes  │         │
│                          └─────────┬──────────┘         │
│                                    │                     │
│                          ┌─────────▼──────────┐         │
│                          │    AWS SES Email    │         │
│                          └──────────────────────┘        │
└──────────────────────────────────────────────────────────┘
```

### File Structure
```
/opt/aws-security-monitor/
├── aws_security_monitor.py    # Main monitoring script
├── requirements.txt           # Python dependencies
├── venv/                      # Python virtual environment
└── setup_production.sh        # Setup automation script

~/.aws-security-monitor/
├── processed_events.pkl       # State file for duplicate prevention
└── aws_security_monitor.log   # Application logs

/var/log/
└── aws-security-monitor.log   # System-level logs
```

---

## Prerequisites

### System Requirements
- **OS**: Ubuntu/Debian Linux (tested on Ubuntu 20.04+)
- **Python**: 3.6 or higher
- **Memory**: Minimum 512MB RAM
- **Storage**: 1GB free space for logs

### AWS Requirements
1. **CloudTrail**: Enabled in all regions you want to monitor
2. **IAM Permissions**: 
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "cloudtrail:LookupEvents",
           "ec2:DescribeInstances",
           "ec2:DescribeRegions",
           "ses:SendEmail",
           "ses:SendRawEmail"
         ],
         "Resource": "*"
       }
     ]
   }
   ```
3. **AWS SES**: 
   - Verified sender email address
   - Production access (out of sandbox)
   - Configured in us-east-1 region

### Network Requirements
- Outbound HTTPS (443) to AWS APIs
- DNS resolution for AWS endpoints

---

## Installation Guide

### Step 1: Prepare the Server
```bash
# Update system
sudo apt-get update
sudo apt-get upgrade -y

# Install required packages
sudo apt-get install -y python3 python3-venv python3-pip git

# Install AWS CLI (if not present)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### Step 2: Configure AWS Credentials
```bash
# Configure AWS profiles
aws configure --profile unified
# Enter: Access Key ID, Secret Access Key, Region (us-east-1), Output format (json)

aws configure --profile bamkom
# Enter credentials for second account

# Verify profiles
aws configure list-profiles
```

### Step 3: Create Installation Directory
```bash
# Create directory structure
sudo mkdir -p /opt/aws-security-monitor
cd /opt/aws-security-monitor

# Set appropriate ownership (replace 'ubuntu' with your username)
sudo chown -R ubuntu:ubuntu /opt/aws-security-monitor
```

### Step 4: Deploy the Script
```bash
# Copy files to production (from local machine)
scp aws_security_monitor.py requirements.txt setup_production.sh user@server:/opt/aws-security-monitor/

# Or clone from repository (if using Git)
git clone <your-repository> /opt/aws-security-monitor/
```

### Step 5: Set Up Virtual Environment
```bash
cd /opt/aws-security-monitor

# Create virtual environment
python3 -m venv venv

# Activate and install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
```

### Step 6: Configure Email Settings
```bash
# Edit the script
nano aws_security_monitor.py

# Locate and update (around lines 1671-1672):
from_email = 'Security Team <alerts@yourdomain.com>'  # Must be SES verified
to_email = 'security-team@yourdomain.com'             # Recipient email

# Save and exit (Ctrl+X, Y, Enter)
```

### Step 7: Test the Script
```bash
# Run manual test
/opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py

# Check logs
tail -f ~/.aws-security-monitor/aws_security_monitor.log
```

### Step 8: Set Up Automated Monitoring
```bash
# Add cron job
crontab -e

# Add this line for 5-minute monitoring:
*/5 * * * * /opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py >> /var/log/aws-security-monitor.log 2>&1

# Save and verify
crontab -l
```

### Step 9: Configure Log Rotation
```bash
# Create logrotate configuration
sudo nano /etc/logrotate.d/aws-security-monitor

# Add the following:
/var/log/aws-security-monitor.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root root
}

/home/*/.aws-security-monitor/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    missingok
}
```

---

## Configuration

### Email Configuration
Located in `aws_security_monitor.py` lines 1671-1672:
```python
from_email = 'Security Team <no-reply@yourdomain.com>'
to_email = 'alerts@yourdomain.com'
```

### Time Window Configuration
Line 1103 in `aws_security_monitor.py`:
```python
start_time = end_time - timedelta(minutes=10)  # Lookback window
```

### Regions to Monitor
Lines 1143-1145 in `aws_security_monitor.py`:
```python
def get_all_regions(self, profile: str) -> List[str]:
    return ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 
            'ap-south-1', 'ap-southeast-1']
```

### Events to Monitor
Add/remove events in the `CRITICAL_EVENTS` set (lines 37-196).

### System Event Filtering
Modify the `_is_system_generated_event()` method (lines 273-393) to add/remove system patterns.

---

## Testing & Validation

### 1. Verify AWS Connectivity
```bash
# Test AWS access for each profile
aws sts get-caller-identity --profile unified
aws sts get-caller-identity --profile bamkom

# Test CloudTrail access
aws cloudtrail lookup-events --max-items 1 --profile unified
```

### 2. Test Email Delivery
```bash
# Test SES configuration
aws ses send-email \
  --from "alerts@yourdomain.com" \
  --to "test@yourdomain.com" \
  --subject "SES Test" \
  --text "Test message" \
  --region us-east-1 \
  --profile unified
```

### 3. Generate Test Events
```bash
# Create a test security group change
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxx \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0 \
  --profile unified

# Wait 5-10 minutes for CloudTrail to record
# Then run the monitor manually
/opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py
```

### 4. Verify State Management
```bash
# Check state file
ls -la ~/.aws-security-monitor/processed_events.pkl

# Clear state to reprocess events (testing only)
rm ~/.aws-security-monitor/processed_events.pkl
```

---

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. No Emails Received
```bash
# Check if script is running
ps aux | grep aws_security_monitor

# Check cron execution
grep aws_security_monitor /var/log/syslog

# Check for events detected
grep "Processed.*events" /var/log/aws-security-monitor.log

# Check for email sending
grep "email sent successfully" ~/.aws-security-monitor/aws_security_monitor.log

# Verify SES is working
aws ses get-send-quota --region us-east-1
```

#### 2. AWS Credentials Error
```bash
# Verify credentials
aws configure list

# Check credential file permissions
ls -la ~/.aws/credentials
chmod 600 ~/.aws/credentials

# Test with specific profile
AWS_PROFILE=unified aws sts get-caller-identity
```

#### 3. CloudTrail Permission Denied
```bash
# Check IAM permissions
aws iam get-user --profile unified
aws iam list-attached-user-policies --user-name <username>

# Test CloudTrail access
aws cloudtrail lookup-events --max-items 1 --profile unified
```

#### 4. High Volume of Alerts
```bash
# Check what's being detected
grep "Processing.*event" ~/.aws-security-monitor/aws_security_monitor.log

# Temporarily increase lookback window to clear backlog
# Edit aws_security_monitor.py line 1103:
# start_time = end_time - timedelta(minutes=60)
```

#### 5. Script Not Running via Cron
```bash
# Check cron service
sudo systemctl status cron

# Check cron logs
grep CRON /var/log/syslog | tail -20

# Test cron command directly
/opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py

# Check PATH issues
which python3
echo $PATH
```

### Debug Mode
Enable detailed logging by setting environment variable:
```bash
# Run with debug output
DEBUG=1 /opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py

# Or modify cron for permanent debug
*/5 * * * * DEBUG=1 /opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py >> /var/log/aws-security-monitor.log 2>&1
```

### Monitoring Commands
```bash
# Real-time log monitoring
tail -f /var/log/aws-security-monitor.log

# Check today's activity
grep "$(date +%Y-%m-%d)" /var/log/aws-security-monitor.log

# Count events by type
grep "event_name" /var/log/aws-security-monitor.log | sort | uniq -c

# Check for errors
grep -i error /var/log/aws-security-monitor.log | tail -20

# Monitor system resources
htop
df -h
free -m
```

---

## Maintenance

### Daily Tasks
1. **Check logs for errors**:
   ```bash
   grep -i error /var/log/aws-security-monitor.log | grep "$(date +%Y-%m-%d)"
   ```

2. **Verify script is running**:
   ```bash
   grep "Starting AWS Security Monitor" /var/log/aws-security-monitor.log | tail -5
   ```

### Weekly Tasks
1. **Review detected events**:
   ```bash
   grep "Processed.*events" /var/log/aws-security-monitor.log | tail -20
   ```

2. **Check disk space**:
   ```bash
   du -sh ~/.aws-security-monitor/
   du -sh /var/log/aws-security-monitor.log
   ```

3. **Verify email delivery**:
   ```bash
   grep "email sent successfully" /var/log/aws-security-monitor.log | wc -l
   ```

### Monthly Tasks
1. **Update dependencies**:
   ```bash
   cd /opt/aws-security-monitor
   source venv/bin/activate
   pip install --upgrade boto3 botocore
   deactivate
   ```

2. **Review and tune filtering rules**:
   - Check for false positives
   - Update CRITICAL_EVENTS if needed
   - Adjust system event filters

3. **Backup configuration**:
   ```bash
   tar -czf aws-monitor-backup-$(date +%Y%m%d).tar.gz /opt/aws-security-monitor/
   ```

### Updating the Script
```bash
# Backup current version
cp /opt/aws-security-monitor/aws_security_monitor.py /opt/aws-security-monitor/aws_security_monitor.py.bak

# Copy new version
scp aws_security_monitor.py user@server:/opt/aws-security-monitor/

# Test new version
/opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py

# If successful, remove backup
rm /opt/aws-security-monitor/aws_security_monitor.py.bak
```

---

## Security Considerations

### 1. Credential Security
- Store AWS credentials securely (mode 600)
- Use IAM roles when running on EC2
- Rotate access keys regularly
- Use separate AWS accounts for monitoring

### 2. Network Security
- Run on private subnet if possible
- Use VPC endpoints for AWS services
- Restrict outbound traffic to AWS IPs only

### 3. Access Control
- Limit server access to authorized personnel
- Use SSH key authentication only
- Implement fail2ban for brute force protection

### 4. Monitoring the Monitor
- Set up CloudWatch alarms for script failures
- Monitor the monitoring server's security
- Regular security audits

### 5. Data Protection
- Encrypt state file if sensitive
- Secure log files (appropriate permissions)
- Consider log shipping to central SIEM

---

## Appendix

### A. Required IAM Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudTrailReadAccess",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "cloudtrail:GetTrailStatus"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EC2ReadAccess",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "ec2:DescribeSecurityGroups"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SESEmailAccess",
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "ses:FromAddress": "alerts@yourdomain.com"
                }
            }
        }
    ]
}
```

### B. Sample Email Output
```
Subject: AWS Security Alert - 2025-08-28 10:30 - 3 Changes Detected

AWS Account: UNIFIED
├─ EC2 Changes (2 events)
│  ├─ RevokeSecurityGroupIngress [CRITICAL]
│  │  Performed by: admin (IAMUser)
│  │  Time: 2025-08-28 10:25:14 UTC
│  │  Changes Made: Removed 1 inbound rule(s) from security group
│  │  • REMOVED: Inbound rule: TCP:3306 from 10.0.0.0/8
│  │
│  └─ AuthorizeSecurityGroupIngress [HIGH]
│     Performed by: developer (IAMUser)
│     Time: 2025-08-28 10:28:22 UTC
│     Changes Made: Added 1 inbound rule(s) to security group
│     • ADDED: Inbound rule: TCP:443 from 0.0.0.0/0
│
└─ IAM Changes (1 event)
   └─ AttachUserPolicy [HIGH]
      Performed by: admin (IAMUser)
      Time: 2025-08-28 10:29:45 UTC
      Changes Made: Attached policy to user
      • MODIFIED: Attached AdministratorAccess to user developer
```

### C. Quick Commands Reference
```bash
# Start monitoring manually
/opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py

# Check if running
ps aux | grep aws_security_monitor

# View recent logs
tail -n 50 /var/log/aws-security-monitor.log

# Check cron jobs
crontab -l

# Clear state (reprocess all events)
rm ~/.aws-security-monitor/processed_events.pkl

# Test with debug
DEBUG=1 /opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py

# Check disk usage
du -sh ~/.aws-security-monitor/

# Count today's events
grep "$(date +%Y-%m-%d)" /var/log/aws-security-monitor.log | grep "Processed" | wc -l
```

### D. Support Contacts
- **AWS Support**: Via AWS Console Support Center
- **Internal Security Team**: security@yourdomain.com
- **System Administrator**: sysadmin@yourdomain.com
- **Developer/Maintainer**: devops@yourdomain.com

---

## Document Information
- **Version**: 1.0
- **Last Updated**: 2025-08-28
- **Author**: Security Operations Team
- **Review Cycle**: Quarterly

---

*End of Document*