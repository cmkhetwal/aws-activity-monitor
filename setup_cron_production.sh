#!/bin/bash

# AWS Security Monitor - Production Cron Setup
# Sets up daily cron job for 8:00 PM IST

set -e

PROJECT_DIR="/opt/aws-security-monitor"
SERVICE_USER="aws-monitor"

echo "=================================================="
echo "Setting up Production Cron Job - Daily 8 PM IST"
echo "=================================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

# Verify installation
if [ ! -f "$PROJECT_DIR/run_monitor.py" ]; then
    echo "❌ AWS Security Monitor not found. Run deploy.sh first."
    exit 1
fi

# Get destination email from user
echo "📧 Email Configuration:"
read -p "Enter destination email address (current: cmkhetwal@hotmail.com): " DEST_EMAIL
DEST_EMAIL=${DEST_EMAIL:-cmkhetwal@hotmail.com}

read -p "Enter sender email address (current: no-reply@bamko.net): " FROM_EMAIL_ADDRESS
FROM_EMAIL_ADDRESS=${FROM_EMAIL_ADDRESS:-no-reply@bamko.net}

read -p "Enter sender name (current: Bamko Security Team): " FROM_NAME
FROM_NAME=${FROM_NAME:-Bamko Security Team}

# Combine name and email
FROM_EMAIL="$FROM_NAME <$FROM_EMAIL_ADDRESS>"

echo "✅ Using emails: From: $FROM_EMAIL, To: $DEST_EMAIL"

# Update email configuration
echo "⚙️ Updating email configuration..."
sed -i "s/SES_FROM_EMAIL = .*/SES_FROM_EMAIL = \"$FROM_EMAIL\"/" $PROJECT_DIR/config.py
sed -i "s/SES_TO_EMAIL = .*/SES_TO_EMAIL = \"$DEST_EMAIL\"/" $PROJECT_DIR/config.py

# Also update the main script
sed -i "s/from_email = .*/from_email = '$FROM_EMAIL'/" $PROJECT_DIR/aws_security_monitor.py
sed -i "s/to_email = .*/to_email = '$DEST_EMAIL'/" $PROJECT_DIR/aws_security_monitor.py

# Convert 8 PM IST to UTC (IST is UTC+5:30, so 8 PM IST = 2:30 PM UTC)
# Cron format: minute hour day month weekday
CRON_TIME="30 14 * * *"  # 2:30 PM UTC = 8:00 PM IST

echo "🕐 Setting up cron job for 8:00 PM IST (14:30 UTC)..."

# Create cron job for the service user
sudo -u $SERVICE_USER crontab -l 2>/dev/null > /tmp/current_cron || echo "" > /tmp/current_cron

# Remove existing aws-security-monitor jobs
grep -v "aws-security-monitor\|run_monitor.py" /tmp/current_cron > /tmp/new_cron || echo "" > /tmp/new_cron

# Add new cron job
echo "$CRON_TIME $PROJECT_DIR/venv/bin/python $PROJECT_DIR/run_monitor.py >> /var/log/aws-security-monitor/cron.log 2>&1" >> /tmp/new_cron

# Install new crontab
sudo -u $SERVICE_USER crontab /tmp/new_cron

# Clean up temp files
rm /tmp/current_cron /tmp/new_cron

# Create logrotate configuration
echo "📝 Setting up log rotation..."
cat > /etc/logrotate.d/aws-security-monitor << EOF
/var/log/aws-security-monitor/*.log {
    daily
    missingok
    rotate 30
    compress
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Set timezone to IST for easier log reading
echo "🌍 Setting server timezone to Asia/Kolkata (IST)..."
timedatectl set-timezone Asia/Kolkata

# Create monitoring script for cron health
cat > $PROJECT_DIR/check_cron_health.sh << 'EOF'
#!/bin/bash
# Health check script for AWS Security Monitor cron job

LOG_FILE="/var/log/aws-security-monitor/cron.log"
LAST_RUN_FILE="/var/lib/aws-security-monitor/last_successful_run"

# Check if cron ran in the last 25 hours (allowing some buffer)
if [ -f "$LAST_RUN_FILE" ]; then
    LAST_RUN=$(cat $LAST_RUN_FILE)
    CURRENT_TIME=$(date +%s)
    TIME_DIFF=$((CURRENT_TIME - LAST_RUN))
    
    # 25 hours = 90000 seconds
    if [ $TIME_DIFF -gt 90000 ]; then
        echo "⚠️ WARNING: AWS Security Monitor hasn't run successfully in the last 25 hours"
        exit 1
    else
        echo "✅ AWS Security Monitor is running normally"
        exit 0
    fi
else
    echo "⚠️ WARNING: No successful run recorded yet"
    exit 1
fi
EOF

chmod +x $PROJECT_DIR/check_cron_health.sh
chown $SERVICE_USER:$SERVICE_USER $PROJECT_DIR/check_cron_health.sh

# Update run_monitor.py to record successful runs
cat >> $PROJECT_DIR/run_monitor.py << 'EOF'

# Record successful run
import time
with open('/var/lib/aws-security-monitor/last_successful_run', 'w') as f:
    f.write(str(int(time.time())))
EOF

echo ""
echo "✅ Production Cron Setup Completed!"
echo ""
echo "📋 Configuration Summary:"
echo "   📧 From: $FROM_EMAIL"
echo "   📧 To: $DEST_EMAIL"
echo "   🕐 Schedule: Daily at 8:00 PM IST (20:00)"
echo "   👤 User: $SERVICE_USER"
echo "   📁 Logs: /var/log/aws-security-monitor/"
echo ""
echo "🔧 Management Commands:"
echo "   • View cron jobs: sudo -u $SERVICE_USER crontab -l"
echo "   • Test manually: sudo -u $SERVICE_USER $PROJECT_DIR/venv/bin/python $PROJECT_DIR/run_monitor.py"
echo "   • Check logs: tail -f /var/log/aws-security-monitor/daily_report.log"
echo "   • Check cron logs: tail -f /var/log/aws-security-monitor/cron.log"
echo "   • Health check: $PROJECT_DIR/check_cron_health.sh"
echo ""
echo "📅 Next Run: Tomorrow at 8:00 PM IST"
echo ""
echo "⚠️ IMPORTANT: Make sure to:"
echo "1. Copy AWS credentials to /home/$SERVICE_USER/.aws/"
echo "2. Verify SES email addresses are configured"
echo "3. Test the setup before production use"