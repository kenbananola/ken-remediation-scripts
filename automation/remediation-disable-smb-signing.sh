#!/bin/bash

CONF="/etc/samba/smb.conf"

# Remove any existing min protocol entries
sudo sed -i '/^[[:space:]]*server min protocol[[:space:]]*=.*/d' "$CONF"
sudo sed -i '/^[[:space:]]*min protocol[[:space:]]*=.*/d' "$CONF"

# Insert secure minimum protocol
if grep -q "^\[global\]" "$CONF"; then
    sudo sed -i '/^\[global\]/a server min protocol = SMB2' "$CONF"
else
    echo -e "\n[global]\nserver min protocol = SMB2" | sudo tee -a "$CONF"
fi

# Restart Samba
sudo systemctl restart smbd 2>/dev/null

# Self delete
rm remediation-disable-smbv1.sh

# Download the script
# wget https://raw.githubusercontent.com/kenbananola/ken-remediation-scripts/refs/heads/main/automation/remediation-disable-smb-signing.sh

# Make executable
# chmod +x remediation-disable-smbv1.sh

# Execute
# ./remediation-disable-smbv1.sh

