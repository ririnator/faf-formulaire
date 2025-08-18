#!/bin/bash

# FAF Production Firewall Configuration
# Configures UFW (Uncomplicated Firewall) for production security

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SSH_PORT="${SSH_PORT:-22}"
HTTP_PORT="${HTTP_PORT:-80}"
HTTPS_PORT="${HTTPS_PORT:-443}"
APP_PORT="${APP_PORT:-3000}"
MONITORING_PORT="${MONITORING_PORT:-3001}"
MONGODB_PORT="${MONGODB_PORT:-27017}"

# Trusted IPs (add your management IPs here)
TRUSTED_IPS="${TRUSTED_IPS:-}"
ADMIN_IPS="${ADMIN_IPS:-}"

echo -e "${BLUE}🔥 FAF Production Firewall Setup${NC}"
echo "=================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root${NC}"
   exit 1
fi

# Install UFW if not present
if ! command -v ufw &> /dev/null; then
    echo -e "${YELLOW}📦 Installing UFW...${NC}"
    apt-get update
    apt-get install -y ufw
fi

# Reset UFW to defaults
echo -e "${YELLOW}🔄 Resetting firewall to defaults...${NC}"
ufw --force reset

# Set default policies
echo -e "${YELLOW}⚙️  Setting default policies...${NC}"
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (be careful not to lock yourself out!)
echo -e "${GREEN}🔓 Allowing SSH on port ${SSH_PORT}...${NC}"
ufw allow ${SSH_PORT}/tcp comment "SSH"

# Allow HTTP and HTTPS
echo -e "${GREEN}🌐 Allowing HTTP/HTTPS traffic...${NC}"
ufw allow ${HTTP_PORT}/tcp comment "HTTP"
ufw allow ${HTTPS_PORT}/tcp comment "HTTPS"

# Allow application port (only from specific sources if configured)
if [[ -n "$TRUSTED_IPS" ]]; then
    echo -e "${GREEN}🔒 Allowing application port ${APP_PORT} from trusted IPs only...${NC}"
    IFS=',' read -ra IPS <<< "$TRUSTED_IPS"
    for ip in "${IPS[@]}"; do
        ufw allow from "$ip" to any port ${APP_PORT} comment "App from $ip"
    done
else
    echo -e "${YELLOW}⚠️  Allowing application port ${APP_PORT} from anywhere (consider restricting)...${NC}"
    ufw allow ${APP_PORT}/tcp comment "Application"
fi

# Restrict monitoring port to admin IPs only
if [[ -n "$ADMIN_IPS" ]]; then
    echo -e "${GREEN}📊 Allowing monitoring port ${MONITORING_PORT} from admin IPs only...${NC}"
    IFS=',' read -ra IPS <<< "$ADMIN_IPS"
    for ip in "${IPS[@]}"; do
        ufw allow from "$ip" to any port ${MONITORING_PORT} comment "Monitoring from $ip"
    done
else
    echo -e "${YELLOW}⚠️  No admin IPs configured - monitoring port will be blocked${NC}"
fi

# Block MongoDB port (should only be accessed locally or via VPN)
echo -e "${RED}🚫 Blocking MongoDB port ${MONGODB_PORT} from external access...${NC}"
ufw deny ${MONGODB_PORT}/tcp comment "Block MongoDB external"

# Allow specific services
echo -e "${GREEN}🔧 Configuring additional services...${NC}"

# Allow NTP for time synchronization
ufw allow out 123/udp comment "NTP out"

# Allow DNS
ufw allow out 53/tcp comment "DNS TCP out"
ufw allow out 53/udp comment "DNS UDP out"

# Allow SMTP for email (if using external email service)
ufw allow out 25/tcp comment "SMTP out"
ufw allow out 587/tcp comment "SMTP TLS out"
ufw allow out 465/tcp comment "SMTP SSL out"

# Rate limiting for SSH to prevent brute force
echo -e "${GREEN}🛡️  Setting up rate limiting for SSH...${NC}"
ufw limit ${SSH_PORT}/tcp comment "SSH rate limit"

# Rate limiting for HTTP/HTTPS
echo -e "${GREEN}🛡️  Setting up rate limiting for web traffic...${NC}"
ufw limit ${HTTP_PORT}/tcp comment "HTTP rate limit"
ufw limit ${HTTPS_PORT}/tcp comment "HTTPS rate limit"

# Advanced rules for common attack patterns
echo -e "${GREEN}🔍 Setting up advanced security rules...${NC}"

# Block common scan ports
SCAN_PORTS=(21 23 25 53 110 135 139 445 993 995 1433 3306 3389 5432 5984 6379 8080 8443 9200 11211)
for port in "${SCAN_PORTS[@]}"; do
    ufw deny ${port}/tcp comment "Block scan port ${port}"
done

# Allow loopback
ufw allow in on lo
ufw allow out on lo

# IPv6 configuration
echo -e "${GREEN}🌐 Configuring IPv6...${NC}"
sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw

# Logging configuration
echo -e "${GREEN}📝 Configuring logging...${NC}"
ufw logging medium

# Enable UFW
echo -e "${YELLOW}🚀 Enabling firewall...${NC}"
echo "y" | ufw enable

# Show status
echo -e "${GREEN}✅ Firewall configuration complete!${NC}"
echo ""
echo -e "${BLUE}📊 Current firewall status:${NC}"
ufw status verbose

echo ""
echo -e "${BLUE}📋 Firewall Summary:${NC}"
echo "==================="
echo "✅ SSH: Port ${SSH_PORT} (rate limited)"
echo "✅ HTTP: Port ${HTTP_PORT} (rate limited)"
echo "✅ HTTPS: Port ${HTTPS_PORT} (rate limited)"
echo "✅ Application: Port ${APP_PORT}"
if [[ -n "$ADMIN_IPS" ]]; then
    echo "✅ Monitoring: Port ${MONITORING_PORT} (admin IPs only)"
else
    echo "❌ Monitoring: Port ${MONITORING_PORT} (blocked - no admin IPs configured)"
fi
echo "❌ MongoDB: Port ${MONGODB_PORT} (blocked externally)"
echo "🛡️  Rate limiting: Enabled for SSH and web traffic"
echo "📝 Logging: Medium level"

echo ""
echo -e "${YELLOW}⚠️  Important Security Notes:${NC}"
echo "1. Ensure you can access SSH before disconnecting"
echo "2. Configure ADMIN_IPS environment variable for monitoring access"
echo "3. MongoDB is blocked externally - use SSH tunnel or VPN for database access"
echo "4. Review firewall logs regularly: sudo ufw status verbose"
echo "5. Consider setting up fail2ban for additional intrusion prevention"

echo ""
echo -e "${GREEN}🔧 Additional Security Recommendations:${NC}"
echo "1. Set up fail2ban: sudo apt install fail2ban"
echo "2. Configure SSH key authentication and disable password auth"
echo "3. Set up automated security updates"
echo "4. Consider using a VPN for administrative access"
echo "5. Regular security audits and log monitoring"

# Create UFW backup
UFW_BACKUP="/etc/ufw/backup-$(date +%Y%m%d-%H%M%S)"
echo -e "${BLUE}💾 Backup created at: ${UFW_BACKUP}${NC}"
cp -r /etc/ufw "$UFW_BACKUP"

echo ""
echo -e "${GREEN}🎉 Firewall setup complete! Your FAF application is now protected.${NC}"