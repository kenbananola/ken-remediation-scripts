#!/bin/bash

# Remove any existing server signing entries
sudo sed -i '/^server signing/d' /etc/samba/smb.conf

# Add mandatory SMB signing under [global]
sudo sed -i '/^\[global\]/a server signing = mandatory' /etc/samba/smb.conf

# Restart Samba
sudo systemctl restart smbd 2>/dev/null

# This will delete the file after you're done so it doesn't stay on the local system
rm remediation-enable-smb-signing.sh

# Download the script
# wget <github url of raw script>

# Make the script executable:
# chmod +x remediation-enable-smb-signing.sh

# Execute the script:
# ./remediation-enable-smb-signing.sh
