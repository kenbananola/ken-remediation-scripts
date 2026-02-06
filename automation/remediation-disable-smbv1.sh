#!/bin/bash

# Disable SMBv1 protocol
sudo sed -i '/^\[global\]/a min protocol = SMB2' /etc/samba/smb.conf

# Restart Samba services
sudo systemctl restart smbd 2>/dev/null
sudo systemctl restart smb 2>/dev/null

# This will delete the file after you're done so it doesn't stay on the local system
rm remediation-disable-smbv1.sh

# Download the script
# wget <github url of raw script>

# Make the script executable:
# chmod +x remediation-disable-smbv1.sh

# Execute the script:
# ./remediation-disable-smbv1.sh
