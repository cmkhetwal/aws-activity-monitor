#!/bin/bash

# AWS Security Monitor - Production Cron Setup Script with Virtual Environment
# This script sets up automated monitoring every 5 minutes using Python venv

set -e

echo "================================================"
echo "AWS Security Monitor - Production Cron Setup"
echo "================================================"

# Configuration
INSTALL_DIR="/opt/aws-security-monitor"
VENV_DIR="${INSTALL_DIR}/venv"
SCRIPT_NAME="aws_security_monitor.py"
LOG_FILE="/var/log/aws-security-monitor.log"
LOG_DIR="$HOME/.aws-security-monitor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root (for /opt and /var/log access)
if [[ $EUID -eq 0 ]]; then
   print_warning "Running as root. The script will be configured for root user."
   print_warning "Consider running as a dedicated service user for better security."
fi

# Check if script exists in the expected location
if [[ ! -f "${INSTALL_DIR}/${SCRIPT_NAME}" ]]; then
    print_error "Script not found at ${INSTALL_DIR}/${SCRIPT_NAME}"
    echo "Please ensure you have copied the files to ${INSTALL_DIR}/"
    echo "Run: sudo mkdir -p ${INSTALL_DIR} && sudo cp aws_security_monitor.py requirements.txt ${INSTALL_DIR}/"
    exit 1
fi

# Check if virtual environment exists
if [[ ! -d "${VENV_DIR}" ]]; then
    print_warning "Virtual environment not found. Creating it now..."
    
    # Check if python3-venv is installed
    if ! dpkg -l | grep -q python3-venv; then
        print_warning "Installing python3-venv..."
        sudo apt-get update
        sudo apt-get install -y python3-venv
    fi
    
    # Create virtual environment
    cd "${INSTALL_DIR}"
    python3 -m venv venv
    print_status "Virtual environment created"
    
    # Install dependencies
    print_warning "Installing dependencies in virtual environment..."
    ${VENV_DIR}/bin/pip install --upgrade pip
    ${VENV_DIR}/bin/pip install -r requirements.txt
    print_status "Dependencies installed"
else
    print_status "Virtual environment found at ${VENV_DIR}"
fi

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}"
print_status "Log directory ensured at ${LOG_DIR}"

# Create system log file with proper permissions
sudo touch "${LOG_FILE}"
sudo chmod 666 "${LOG_FILE}"
print_status "System log file created at ${LOG_FILE}"

# Test the script with virtual environment
print_warning "Testing the script with virtual environment..."
if ${VENV_DIR}/bin/python ${INSTALL_DIR}/${SCRIPT_NAME} > /tmp/aws-monitor-test.log 2>&1; then
    print_status "Script test successful!"
    echo "Test output saved to /tmp/aws-monitor-test.log"
else
    print_error "Script test failed! Check /tmp/aws-monitor-test.log for errors"
    cat /tmp/aws-monitor-test.log
    exit 1
fi

# Check AWS credentials
print_warning "Checking AWS credentials..."
if aws sts get-caller-identity > /dev/null 2>&1; then
    print_status "AWS credentials are configured"
    IDENTITY=$(aws sts get-caller-identity --output text --query 'Account')
    echo "    Using AWS Account: ${IDENTITY}"
else
    print_error "AWS credentials are not configured. Please run 'aws configure' first."
fi

# Create the cron job
CRON_JOB="*/5 * * * * ${VENV_DIR}/bin/python ${INSTALL_DIR}/${SCRIPT_NAME} >> ${LOG_FILE} 2>&1"

# Check if cron job already exists
if crontab -l 2>/dev/null | grep -q "${SCRIPT_NAME}"; then
    print_warning "Existing cron job found for ${SCRIPT_NAME}"
    echo "Current cron job:"
    crontab -l | grep "${SCRIPT_NAME}"
    
    read -p "Do you want to replace it? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Keeping existing cron job. Exiting."
        exit 0
    fi
    
    # Remove existing cron job
    (crontab -l 2>/dev/null | grep -v "${SCRIPT_NAME}") | crontab -
    print_status "Removed existing cron job"
fi

# Add new cron job
(crontab -l 2>/dev/null; echo "${CRON_JOB}") | crontab -
print_status "Cron job added successfully!"

# Verify cron job was added
echo ""
echo "Current cron configuration:"
crontab -l | grep "${SCRIPT_NAME}"

# Create log rotation configuration
if [[ $EUID -eq 0 ]]; then
    cat > /etc/logrotate.d/aws-security-monitor << EOF
${LOG_FILE} {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root root
    sharedscripts
    postrotate
        # Optional: Send signal to any monitoring service
    endscript
}

${LOG_DIR}/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    missingok
    create 640 $(whoami) $(whoami)
}
EOF
    print_status "Log rotation configured"
fi

# Create systemd service (optional - for better management)
if [[ $EUID -eq 0 ]]; then
    print_warning "Would you like to create a systemd timer as an alternative to cron? (y/n): "
    read -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > /etc/systemd/system/aws-security-monitor.service << EOF
[Unit]
Description=AWS Security Monitor
After=network.target

[Service]
Type=oneshot
User=$(whoami)
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/${SCRIPT_NAME}
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF

        cat > /etc/systemd/system/aws-security-monitor.timer << EOF
[Unit]
Description=Run AWS Security Monitor every 5 minutes
Requires=aws-security-monitor.service

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

        systemctl daemon-reload
        systemctl enable aws-security-monitor.timer
        systemctl start aws-security-monitor.timer
        print_status "Systemd timer created and started"
        echo "You can check status with: systemctl status aws-security-monitor.timer"
    fi
fi

echo ""
echo "================================================"
echo "          Setup Complete!"
echo "================================================"
echo ""
echo "The AWS Security Monitor will run every 5 minutes."
echo ""
echo "📋 Important Commands:"
echo "   View cron jobs:           crontab -l"
echo "   Edit cron jobs:           crontab -e"
echo "   Monitor application logs:  tail -f ${LOG_DIR}/aws_security_monitor.log"
echo "   Monitor system logs:      tail -f ${LOG_FILE}"
echo "   Test script manually:      ${VENV_DIR}/bin/python ${INSTALL_DIR}/${SCRIPT_NAME}"
echo ""
echo "📧 Email Configuration:"
echo "   Remember to update the email settings in ${INSTALL_DIR}/${SCRIPT_NAME}:"
echo "   - Line 981: from_email = 'your-verified-email@domain.com'"
echo "   - Line 982: to_email = 'your-alerts@domain.com'"
echo ""
echo "🔒 Security Reminders:"
echo "   1. Verify SES email addresses are configured"
echo "   2. Check IAM permissions for CloudTrail access"
echo "   3. Ensure AWS credentials are properly secured"
echo ""

# Wait for first execution
echo "Waiting 30 seconds for first execution..."
sleep 30

# Check if log file has been updated
if [[ -f "${LOG_FILE}" ]] && [[ $(find "${LOG_FILE}" -mmin -1 2>/dev/null) ]]; then
    print_status "Monitor is running! Recent log entries:"
    tail -n 5 "${LOG_FILE}"
else
    print_warning "No recent log entries. Check the logs manually:"
    echo "    tail -f ${LOG_FILE}"
fi

echo ""
echo "Setup complete! The monitor is now active."