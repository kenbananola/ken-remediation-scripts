#!/bin/bash

# Remediation for Tenable Plugin ID 57608
# Vulnerability: SMB Signing Not Required
# Fix: Enforce mandatory SMB signing

CONF="/etc/samba/smb.conf"

# Remove any existing server signing entries
sudo sed -i '/^[[:space:]]*server signing[[:space:]]*=.*/d' "$CONF"

# Insert mandatory signing under [global]
if grep -q "^\[global\]" "$CONF"; then
    sudo sed -i '/^\[global\]/a server signing = mandatory' "$CONF"
else
    echo -e "\n[global]\nserver signing = mandatory" | sudo tee -a "$CONF"
fi

# Restart Samba service
sudo systemctl restart smbd 2>/dev/null

# This will delete the file after you're done so it doesn't stay on the local system
rm remediation-enable-smb-signing.sh

# Download the script
# wget https://raw.githubusercontent.com/kenbananola/ken-remediation-scripts/refs/heads/main/automation/remediation-enable-smb-signing.sh

# Make the script executable:
# chmod +x remediation-enable-smb-signing.sh

# Execute the script:
# ./remediation-enable-smb-signing.sh
