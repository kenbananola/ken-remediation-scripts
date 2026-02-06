#!/bin/bash

# Enforce SMB signing
sudo sed -i '/^\[global\]/a server signing = mandatory' /etc/samba/smb.conf

# Restart Samba
sudo systemctl restart smbd 2>/dev/null

# This will delete the file after you're done so it doesn't stay on the local system
rm remediation-enable-smb-signing.sh

# Download the script
# wget https://raw.githubusercontent.com/kenbananola/ken-remediation-scripts/main/automation/remediation-enable-smb-signing.sh

# Make the script executable:
# chmod +x remediation-enable-smb-signing.sh

# Execute the script:
# ./remediation-enable-smb-signing.sh
