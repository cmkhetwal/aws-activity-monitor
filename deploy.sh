#!/bin/bash

# AWS Security Monitor - Production Deployment Script for Ubuntu
# This script deploys the monitoring system to a production Ubuntu server

set -e

echo "=================================================="
echo "AWS Security Monitor - Production Deployment"
echo "=================================================="

# Variables
PROJECT_DIR="/opt/aws-security-monitor"
SERVICE_USER="aws-monitor"
LOG_DIR="/var/log/aws-security-monitor"
DATA_DIR="/var/lib/aws-security-monitor"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

echo "🚀 Starting deployment..."

# Update system packages
echo "📦 Updating system packages..."
apt update
apt install -y python3 python3-pip python3-venv git cron awscli

# Create service user
echo "👤 Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/bash -m -d /home/$SERVICE_USER $SERVICE_USER
    echo "✅ Created user: $SERVICE_USER"
else
    echo "ℹ️ User $SERVICE_USER already exists"
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p $PROJECT_DIR
mkdir -p $LOG_DIR
mkdir -p $DATA_DIR

# Set ownership
chown -R $SERVICE_USER:$SERVICE_USER $PROJECT_DIR
chown -R $SERVICE_USER:$SERVICE_USER $LOG_DIR
chown -R $SERVICE_USER:$SERVICE_USER $DATA_DIR

# Copy project files
echo "📋 Copying project files..."
cp aws_security_monitor.py $PROJECT_DIR/
cp requirements.txt $PROJECT_DIR/
cp README.md $PROJECT_DIR/

# Create Python virtual environment
echo "🐍 Setting up Python environment..."
sudo -u $SERVICE_USER python3 -m venv $PROJECT_DIR/venv
sudo -u $SERVICE_USER $PROJECT_DIR/venv/bin/pip install --upgrade pip
sudo -u $SERVICE_USER $PROJECT_DIR/venv/bin/pip install -r $PROJECT_DIR/requirements.txt

# Create production configuration
echo "⚙️ Creating production configuration..."
cat > $PROJECT_DIR/config.py << 'EOF'
#!/usr/bin/env python3
"""
Production configuration for AWS Security Monitor
"""

# Email settings
SES_FROM_EMAIL = "no-reply@bamko.net"
SES_TO_EMAIL = "cmkhetwal@hotmail.com"
SES_REGION = "us-east-1"
SES_PROFILE = "unified"

# Monitoring settings
CLOUDTRAIL_LOOKBACK_MINUTES = 1440  # 24 hours for daily reports
MONITOR_PROFILES = ["default", "unified"]

# Paths
LOG_DIR = "/var/log/aws-security-monitor"
STATE_DIR = "/var/lib/aws-security-monitor"
EOF

chown $SERVICE_USER:$SERVICE_USER $PROJECT_DIR/config.py

# Create production wrapper script
echo "📝 Creating production wrapper script..."
cat > $PROJECT_DIR/run_monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Production wrapper for AWS Security Monitor
Runs daily security report for all changes in the last 24 hours
"""

import sys
import os

# Add project directory to path
sys.path.insert(0, '/opt/aws-security-monitor')

# Import the main monitor class
from aws_security_monitor import AWSSecurityMonitor
import logging
from datetime import datetime, timedelta, timezone

# Configure production logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/aws-security-monitor/daily_report.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('DailySecurityReport')

class DailySecurityMonitor(AWSSecurityMonitor):
    """Enhanced monitor for daily reports"""
    
    def fetch_cloudtrail_events(self, profile: str, region: str):
        """Fetch CloudTrail events for the last 24 hours"""
        try:
            import boto3
            session = boto3.Session(profile_name=profile, region_name=region)
            cloudtrail = session.client('cloudtrail')
            
            # Get events from last 24 hours
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=24)
            
            logger.info(f"Fetching events from {start_time} to {end_time} in {region}")
            
            events = []
            paginator = cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50
            ):
                for event in page.get('Events', []):
                    event_name = event.get('EventName', '')
                    
                    if self._should_monitor_event(event_name):
                        events.append(event)
            
            logger.info(f"Found {len(events)} security events in {region}")
            return events
            
        except Exception as e:
            logger.error(f"Error fetching CloudTrail events for {profile} in {region}: {e}")
            return []

def main():
    """Run daily security report"""
    logger.info("=" * 60)
    logger.info("DAILY AWS SECURITY REPORT - " + datetime.now().strftime('%Y-%m-%d %H:%M:%S IST'))
    logger.info("=" * 60)
    
    try:
        monitor = DailySecurityMonitor()
        
        # Don't use state file for daily reports - always get last 24 hours
        monitor.processed_events = set()
        
        # Run monitoring
        monitor.monitor_all_accounts()
        
        # Generate and send report
        if monitor.events_to_notify:
            html_content = monitor.generate_html_email()
            if html_content:
                # Update subject for daily report
                monitor.send_email_notification(html_content)
                
                total_events = sum(len(events) for profile_events in monitor.events_to_notify.values() 
                                 for events in profile_events.values())
                logger.info(f"✅ Daily security report sent - {total_events} events detected")
            else:
                logger.info("❌ Failed to generate email content")
        else:
            logger.info("✅ Daily report: No security events detected in the last 24 hours")
            
    except Exception as e:
        logger.error(f"❌ Daily report failed: {e}")
        sys.exit(1)
    
    logger.info("=" * 60)
    logger.info("DAILY REPORT COMPLETED")
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
EOF

chmod +x $PROJECT_DIR/run_monitor.py
chown $SERVICE_USER:$SERVICE_USER $PROJECT_DIR/run_monitor.py

# Create systemd service (optional, for better process management)
echo "⚙️ Creating systemd service..."
cat > /etc/systemd/system/aws-security-monitor.service << EOF
[Unit]
Description=AWS Security Monitor Daily Report
After=network.target

[Service]
Type=oneshot
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$PROJECT_DIR
Environment=PATH=/opt/aws-security-monitor/venv/bin
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/run_monitor.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo "✅ Deployment completed!"
echo ""
echo "📋 Next Steps:"
echo "1. Copy your AWS credentials to /home/$SERVICE_USER/.aws/"
echo "2. Test the installation:"
echo "   sudo -u $SERVICE_USER $PROJECT_DIR/venv/bin/python $PROJECT_DIR/run_monitor.py"
echo "3. Set up the cron job (see setup_cron_production.sh)"
echo ""
echo "📁 Installation locations:"
echo "   - Application: $PROJECT_DIR"
echo "   - Logs: $LOG_DIR"
echo "   - Data: $DATA_DIR"
echo "   - User: $SERVICE_USER"
echo ""
echo "🔧 Management commands:"
echo "   - Run manually: sudo systemctl start aws-security-monitor"
echo "   - Check logs: journalctl -u aws-security-monitor"
echo "   - Check status: systemctl status aws-security-monitor"