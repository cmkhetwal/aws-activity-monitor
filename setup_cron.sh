#!/bin/bash

# AWS Security Monitor - Cron Setup Script

echo "Setting up AWS Security Monitor..."

# Create necessary directories
mkdir -p ~/.aws-security-monitor

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Install Python dependencies
echo "Installing dependencies..."
source venv/bin/activate
pip install -r requirements.txt

# Make script executable
chmod +x aws_security_monitor.py

# Add to crontab (runs every 5 minutes)
SCRIPT_DIR="$(pwd)"
CRON_JOB="*/5 * * * * cd $SCRIPT_DIR && $SCRIPT_DIR/venv/bin/python $SCRIPT_DIR/aws_security_monitor.py >> ~/.aws-security-monitor/cron.log 2>&1"

# Check if cron job already exists
(crontab -l 2>/dev/null | grep -q "aws_security_monitor.py") && echo "Cron job already exists" || {
    (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
    echo "Cron job added successfully"
}

echo "Setup complete!"
echo ""
echo "✅ Email configuration (AWS SES):"
echo "   From: Bamko Security Team <no-reply@bamko.net>"
echo "   To: cmkhetwal@hotmail.com"
echo ""
echo "Important notes:"
echo "1. AWS credentials are configured in ~/.aws/credentials"
echo "2. CloudTrail must be enabled in regions you want to monitor"
echo "3. AWS SES is configured for email sending"
echo "4. Ensure SES sender email (no-reply@bamko.net) is verified in SES console"
echo ""
echo "To test the script manually:"
echo "  source venv/bin/activate && python aws_security_monitor.py"
echo ""
echo "To generate test events:"
echo "  source venv/bin/activate && python test_trigger_events.py"
echo ""
echo "To view logs:"
echo "  tail -f ~/.aws-security-monitor/aws_security_monitor.log"
echo ""
echo "To view cron logs:"
echo "  tail -f ~/.aws-security-monitor/cron.log"
echo ""
echo "To remove from cron:"
echo "  crontab -l | grep -v aws_security_monitor | crontab -"