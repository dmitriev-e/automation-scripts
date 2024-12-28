#!/bin/bash

# Description: This script disables password authentication for SSH and enables public key authentication.

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or using sudo."
  exit 1
fi

# Path to the SSH configuration file
SSH_CONFIG_FILE="/etc/ssh/sshd_config"

# Backup the SSH configuration file
BACKUP_FILE="${SSH_CONFIG_FILE}.bak.$(date +%F)"
echo "Backing up SSH configuration to $BACKUP_FILE"
cp "$SSH_CONFIG_FILE" "$BACKUP_FILE"

# Update the configuration to disable password authentication
if grep -q '^#\?PasswordAuthentication' "$SSH_CONFIG_FILE"; then
  echo "Updating PasswordAuthentication setting to 'no'"
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONFIG_FILE"
else
  echo "Adding PasswordAuthentication no to the configuration file"
  echo "PasswordAuthentication no" >> "$SSH_CONFIG_FILE"
fi

# Ensure ChallengeResponseAuthentication is disabled
if grep -q '^#\?ChallengeResponseAuthentication' "$SSH_CONFIG_FILE"; then
  echo "Updating ChallengeResponseAuthentication setting to 'no'"
  sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSH_CONFIG_FILE"
else
  echo "Adding ChallengeResponseAuthentication no to the configuration file"
  echo "ChallengeResponseAuthentication no" >> "$SSH_CONFIG_FILE"
fi

# Enable public key authentication
if grep -q '^#?PubkeyAuthentication' "$SSH_CONFIG_FILE"; then
  echo "Updating PubkeyAuthentication setting to 'yes'"
  sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSH_CONFIG_FILE"
else
  echo "Setting PubkeyAuthentication to 'yes'"
  echo "PubkeyAuthentication yes" >> "$SSH_CONFIG_FILE"
fi

# Restart SSH service
echo "Restarting SSH service"
systemctl restart sshd

# Verify if the changes are effective
if systemctl status sshd | grep -q running; then
  echo "Password authentication has been disabled and public key authentication has been enabled successfully."
else
  echo "There was an issue restarting the SSH service. Please check manually."
  exit 1
fi
