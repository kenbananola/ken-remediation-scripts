#!/bin/bash

CONF="/etc/samba/smb.conf"

# Remove any existing server signing entries
sudo sed -i '/^[[:space:]]*server signing[[:space:]]*=.*/d' "$CONF"

# If [global] exists, insert under it
if grep -q "^\[global\]" "$CONF"; then
    sudo sed -i '/^\[global\]/a server signing = mandatory' "$CONF"
else
    # If no [global], create it
    echo -e "\n[global]\nserver signing = mandatory" | sudo tee -a "$CONF"
fi

# Restart Samba
sudo systemctl restart smbd 2>/dev/null

# Self-delete
rm remediation-enable-smb-signing.sh

# Download the script
# wget <github url of raw script>

# Make executable
# chmod +x remediation-enable-smb-signing.sh

# Execute
# ./remediation-enable-smb-signing.sh
