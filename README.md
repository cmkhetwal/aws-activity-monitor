# AWS Activity Monitor

🚨 **Real-time AWS infrastructure change detection and alerting system with CloudTrail-level detail**

## 🎯 Overview

AWS Activity Monitor is an enterprise-grade security monitoring solution that tracks critical infrastructure changes across multiple AWS accounts in real-time. It provides detailed email alerts showing exactly what changed, who changed it, and the complete before/after details - similar to CloudTrail but with intelligent filtering and executive-friendly formatting.

## ✨ Key Features

- 🔍 **Comprehensive Monitoring**: Tracks 200+ critical AWS API calls across all major services
- 📧 **Detailed Alerts**: HTML-formatted emails with complete change summaries
- 🎯 **Smart Filtering**: Automatically excludes system-generated events (AWS service roles, automated backups)
- 🏢 **Multi-Account Support**: Monitors all AWS profiles configured in ~/.aws/credentials
- 🌍 **Multi-Region Coverage**: Scans all major AWS regions automatically
- 🔄 **Real-time Detection**: 5-minute monitoring intervals with 10-minute lookback windows
- 📊 **Change Tracking**: Shows exactly what was added, removed, or modified
- 🚫 **Duplicate Prevention**: State management prevents duplicate alerts
- 📋 **Categorized Alerts**: Groups events by service (EC2, IAM, S3, etc.) with severity levels

## 🛡️ What Gets Monitored

### Security & IAM
- User, role, and policy creation/deletion/modification
- Access key management and MFA changes
- Permission attachments and password policy updates

### Infrastructure
- EC2 instance lifecycle (launch, terminate, stop, start) with instance names
- Security group modifications with exact rule details
- VPC and network changes
- Load balancer configurations

### Data & Storage
- S3 bucket policies and public access settings
- RDS instance modifications
- DynamoDB table changes
- EBS volume and snapshot management

### Application Services
- Lambda function deployments and permission changes
- API Gateway modifications
- SSM command executions and parameter changes

## 📧 Sample Alert Output

```
Subject: AWS Security Alert - 2025-08-28 10:30 - 2 Changes Detected

AWS Account: PRODUCTION
├─ EC2 Changes (1 event)
│  └─ RevokeSecurityGroupIngress [CRITICAL]
│     Performed by: john.doe (IAMUser)
│     Time: 2025-08-28 10:25:14 UTC
│     Region: us-west-2
│     Source IP: 203.0.113.1
│     
│     Changes Made: Removed 1 inbound rule(s) from security group
│     • REMOVED: Inbound rule: TCP:3306 from 10.0.0.0/8 (Database Access)
│     
│     Resources: SecurityGroup: sg-080869f422db6cd5c
│
└─ IAM Changes (1 event)
   └─ AttachUserPolicy [HIGH]
      Performed by: admin (IAMUser)  
      Time: 2025-08-28 10:29:45 UTC
      
      Changes Made: Attached policy to user developer
      • MODIFIED: Attached AdministratorAccess policy to user developer
```

## 🚀 Quick Start

### Prerequisites
- Python 3.6 or higher
- AWS CLI configured with profiles
- CloudTrail enabled in target regions
- AWS SES configured with verified sender email

### Installation
```bash
# Clone the repository
git clone https://github.com/cmkhetwal/aws-activity-monitor.git
cd aws-activity-monitor

# Run automated setup
chmod +x setup_production.sh
sudo ./setup_production.sh
```

### Manual Installation
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure email settings in the script
nano aws_security_monitor.py
# Update lines 1671-1672 with your email addresses

# Test the script
./venv/bin/python aws_security_monitor.py

# Set up automated monitoring (every 5 minutes)
crontab -e
# Add: */5 * * * * /path/to/venv/bin/python /path/to/aws_security_monitor.py >> /var/log/aws-security-monitor.log 2>&1
```

## ⚙️ Configuration

### Email Settings
Update the following lines in `aws_security_monitor.py`:
```python
from_email = 'Security Team <alerts@yourdomain.com>'  # Must be SES verified
to_email = 'security-team@yourdomain.com'             # Alert recipient
```

### AWS Profiles
The script automatically detects all profiles in `~/.aws/credentials`:
```ini
[production]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
region = us-east-1

[staging]  
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
region = us-west-2
```

### Monitored Regions
By default monitors: `us-east-1`, `us-west-2`, `eu-west-1`, `eu-central-1`, `ap-south-1`, `ap-southeast-1`

Modify the `get_all_regions()` method to add/remove regions.

## 🔧 Advanced Configuration

### Custom Event Filtering
Add/remove events from the `CRITICAL_EVENTS` set in the script to customize what gets monitored.

### System Event Exclusions  
The script automatically filters out AWS service roles and automated processes. Modify `_is_system_generated_event()` to customize filtering.

### Monitoring Frequency
Default: Every 5 minutes with 10-minute lookback window. Adjust in crontab and script timedelta.

## 📚 Documentation

- **[Standard Operating Procedure (SOP)](SOP_AWS_Security_Monitor.md)** - Complete setup and maintenance guide
- **[Production Deployment Guide](PRODUCTION_DEPLOYMENT.md)** - Production deployment instructions
- **[IAM Policy](examples/iam_policy.json)** - Required AWS permissions

## 🔍 Troubleshooting

### Common Issues

**No emails received:**
```bash
# Check if script is running
ps aux | grep aws_security_monitor

# Check logs
tail -f /var/log/aws-security-monitor.log

# Test SES configuration
aws ses send-email --from alerts@domain.com --to test@domain.com --subject "Test" --text "Test"
```

**AWS credentials error:**
```bash
# Verify profiles
aws configure list-profiles
aws sts get-caller-identity --profile production
```

**Debug mode:**
```bash
DEBUG=1 ./venv/bin/python aws_security_monitor.py
```

## 🛠️ System Requirements

### Server Requirements
- **OS**: Ubuntu/Debian Linux
- **Python**: 3.6+
- **Memory**: 512MB+ RAM
- **Storage**: 1GB+ for logs

### AWS Requirements
- CloudTrail enabled in target regions
- SES configured and verified
- IAM permissions for CloudTrail:LookupEvents, EC2:DescribeInstances, SES:SendEmail

## 🔒 Security Considerations

- Use IAM roles when running on EC2
- Restrict file permissions (chmod 600 ~/.aws/credentials)
- Monitor the monitoring server
- Regular security audits
- Encrypt logs if sensitive

## 📊 Monitoring Stats

- **Events Processed**: 200+ AWS API types
- **Detection Speed**: 5-minute intervals  
- **Lookback Window**: 10 minutes (configurable)
- **Duplicate Prevention**: State-based tracking
- **Multi-Region**: 6 major regions by default
- **Multi-Account**: Unlimited AWS profiles

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/cmkhetwal/aws-activity-monitor/issues)
- **Documentation**: [SOP Guide](SOP_AWS_Security_Monitor.md)
- **Email**: Create an issue for support requests

## 🏷️ Tags

`aws` `security` `monitoring` `cloudtrail` `alerts` `python` `devops` `cloud-security` `aws-security` `infrastructure-monitoring`

---

**⭐ If this project helps you monitor your AWS infrastructure, please give it a star!**