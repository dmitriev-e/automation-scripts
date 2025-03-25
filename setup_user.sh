#!/bin/bash

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Ask for username
read -p "Enter username to create: " username

# Ask for password (hidden input)
read -s -p "Enter password for $username: " password
echo

# Create new user
adduser $username

# Set password for the user
echo "$username:$password" | chpasswd

# Add user to sudo group
usermod -aG sudo $username

# Configure sudo without password for the user
echo "$username ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$username

# Create .ssh directory for the user
mkdir -p /home/$username/.ssh
chmod 700 /home/$username/.ssh

# Create authorized_keys file and add SSH key
touch  /home/$username/.ssh/authorized_keys
chmod 600 /home/$username/.ssh/authorized_keys

# Set correct ownership
chown -R $username:$username /home/$username/.ssh

echo "User setup completed successfully!"
echo "SSH key has been added to authorized_keys"
