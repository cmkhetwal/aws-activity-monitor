# Production Deployment Guide - AWS Security Monitor

## Files to Transfer to Production Server

Transfer these files to your production server:
```
aws_security_monitor.py
requirements.txt
setup_cron_production.sh
```

## Email Configuration Changes

### 1. Update Email Settings in `aws_security_monitor.py`

**Line 981-982:** Change sender and receiver emails
```python
# Current (Development):
from_email = 'Bamko Security Team <no-reply@bamko.net>'
to_email = 'cmkhetwal@hotmail.com'

# Change to (Production):
from_email = 'Your Security Team <your-verified-ses-email@yourdomain.com>'
to_email = 'your-production-alerts@yourdomain.com'
```

### 2. Update SES Profile if needed

**Line 975:** Update the SES profile name
```python
# Current:
ses_profile = 'unified' if 'unified' in self.profiles else 'default'

# Change to your production profile:
ses_profile = 'production' if 'production' in self.profiles else 'default'
```

## Production Setup Steps

### 1. Create Directory Structure
```bash
# On production server
mkdir -p /opt/aws-security-monitor
cd /opt/aws-security-monitor

# Copy files here
# scp from local machine:
# scp aws_security_monitor.py requirements.txt setup_cron_production.sh user@production-server:/opt/aws-security-monitor/
```

### 2. Set Up Python Virtual Environment
```bash
# Install python3-venv if not available
sudo apt-get update
sudo apt-get install python3-venv

# Create virtual environment
cd /opt/aws-security-monitor
python3 -m venv venv

# Activate and install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
```

### 3. Configure AWS Credentials
```bash
# Ensure AWS credentials are configured
aws configure list-profiles

# Or copy credentials from development
mkdir -p ~/.aws
# Then copy your credentials and config files
```

### 4. Test the Script
```bash
# Test with virtual environment
cd /opt/aws-security-monitor
./venv/bin/python aws_security_monitor.py

# Check logs
tail -f ~/.aws-security-monitor/aws_security_monitor.log
```

### 5. Set Up Cron with Virtual Environment
```bash
# Make setup script executable
chmod +x setup_cron_production.sh

# Run setup script
./setup_cron_production.sh
```

## Cron Configuration with Virtual Environment

The cron entry will look like this:
```bash
*/5 * * * * /opt/aws-security-monitor/venv/bin/python /opt/aws-security-monitor/aws_security_monitor.py >> /var/log/aws-security-monitor.log 2>&1
```

## Verification Steps

1. **Check cron is running:**
   ```bash
   crontab -l
   ```

2. **Monitor logs:**
   ```bash
   tail -f ~/.aws-security-monitor/aws_security_monitor.log
   tail -f /var/log/aws-security-monitor.log
   ```

3. **Verify SES configuration:**
   ```bash
   # Test SES sending capability
   aws ses send-email \
     --from "your-verified-email@domain.com" \
     --to "test@domain.com" \
     --subject "Test" \
     --text "Test message" \
     --region us-east-1 \
     --profile production
   ```

## Important Production Considerations

### Security
- Use IAM roles if running on EC2
- Restrict file permissions:
  ```bash
  chmod 600 ~/.aws/credentials
  chmod 700 /opt/aws-security-monitor
  chmod 600 /opt/aws-security-monitor/aws_security_monitor.py
  ```

### Monitoring
- Set up CloudWatch alarms for script failures
- Monitor disk space for log files
- Set up log rotation:
  ```bash
  # Create /etc/logrotate.d/aws-security-monitor
  /var/log/aws-security-monitor.log {
      daily
      rotate 30
      compress
      delaycompress
      notifempty
      create 640 root root
  }
  ```

### High Availability
- Consider running on multiple servers for redundancy
- Use a shared state store (e.g., DynamoDB) instead of local pickle file
- Implement health checks

## Rollback Plan
If issues occur:
1. Remove cron entry: `crontab -e`
2. Restore previous monitoring solution
3. Check logs for root cause analysis

## Support Contacts
- AWS Support: [Your AWS support plan]
- Security Team: [Your security team contact]
- DevOps Team: [Your DevOps team contact]