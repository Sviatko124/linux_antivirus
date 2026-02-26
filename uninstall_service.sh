#!/bin/bash

echo "Uninstalling Antivirus Service..."

sudo systemctl stop antivirus.service
sudo systemctl disable antivirus.service

sudo rm -f /etc/systemd/system/antivirus.service

sudo systemctl daemon-reload

sudo rm -f /usr/local/bin/antivirus_service.py

sudo rm -rf /var/lib/antivirus

sudo rm -f /var/log/antivirus.log

echo "Antivirus Service Uninstalled."

