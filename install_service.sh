#!/bin/bash

echo "Installing Antivirus Service..."

sudo mkdir -p /var/lib/antivirus
sudo mkdir -p /var/lib/antivirus/quarantine

sudo cp signatures_sha256.txt /var/lib/antivirus/

sudo cp av_service.py /usr/local/bin/antivirus_service.py
sudo chmod +x /usr/local/bin/antivirus_service.py

sudo touch /var/log/antivirus.log
sudo chmod 644 /var/log/antivirus.log

sudo bash -c 'cat > /etc/systemd/system/antivirus.service <<EOF
[Unit]
Description=Custom Antivirus Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/antivirus_service.py /home
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl enable antivirus.service
sudo systemctl start antivirus.service

echo "Antivirus Service Installed and Started."

