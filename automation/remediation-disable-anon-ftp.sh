#!/bin/bash

# Disable anonymous FTP login
sudo sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf

# Restart FTP service
sudo systemctl restart vsftpd

# This will delete the file after you're done so it doesn't stay on the local system
rm remediation-disable-anon-ftp.sh

# Download the script
# wget <github url of raw script>

# Make the script executable:
# chmod +x remediation-disable-anon-ftp.sh

# Execute the script:
# ./remediation-disable-anon-ftp.sh
