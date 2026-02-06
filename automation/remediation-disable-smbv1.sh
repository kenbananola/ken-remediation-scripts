#!/bin/bash

# Disable SMBv1 by forcing SMB2 minimum
sudo sed -i 's/^server min protocol =.*/server min protocol = SMB2/' /etc/samba/smb.conf

# Restart Samba service
sudo systemctl restart smbd 2>/dev/null

# This will delete the file after you're done so it doesn't stay on the local system
rm remediation-disable-smbv1.sh

# Download the script
# wget https://raw.githubusercontent.com/kenbananola/ken-remediation-scripts/main/automation/remediation-disable-smbv1.sh

# Make the script executable:
# chmod +x remediation-disable-smbv1.sh

# Execute the script:
# ./remediation-disable-smbv1.sh
