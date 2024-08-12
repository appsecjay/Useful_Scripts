#!/bin/bash

# Define the period of inactivity
# Bash Script to Find and Remove Old Unused Packages
PERIOD="2 years 3 months"

# Define the log file location
LOG_FILE="/var/log/apt/history.log"

# Temporary file to store package usage information
TEMP_FILE="/tmp/unused_packages.txt"

# Update package list and upgrade the system
sudo apt-get update
sudo apt-get upgrade -y

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
  echo "APT log file does not exist. Check if the log file path is correct."
  exit 1
fi

# Parse the log file for package installation and removal information
grep -E "Start-Date:|Remove:|Install:" "$LOG_FILE" > "$TEMP_FILE"

# Filter out packages installed or removed more than the defined period ago
# Find the date of interest (2 years 3 months ago)
TARGET_DATE=$(date -d "now - $PERIOD" +'%Y-%m-%d')

# Function to parse date and compare with target date
is_package_old() {
  local package_date="$1"
  local package_name="$2"
  if [ "$(date -d "$package_date" +%s)" -lt "$(date -d "$TARGET_DATE" +%s)" ]; then
    echo "$package_name"
  fi
}

# Get the list of all installed packages
dpkg --get-selections | grep -v deinstall | awk '{print $1}' > /tmp/installed_packages.txt

# Parse and identify old packages
while IFS= read -r line; do
  if [[ "$line" =~ ^Start-Date:\ ([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
    INSTALL_DATE="${BASH_REMATCH[1]}"
  elif [[ "$line" =~ ^Install:\ (.*) ]]; then
    PACKAGE_NAME="${BASH_REMATCH[1]}"
    if [[ "$(is_package_old "$INSTALL_DATE" "$PACKAGE_NAME")" ]]; then
      echo "$PACKAGE_NAME" >> /tmp/old_packages.txt
    fi
  elif [[ "$line" =~ ^Remove:\ (.*) ]]; then
    PACKAGE_NAME="${BASH_REMATCH[1]}"
    if [[ "$(is_package_old "$INSTALL_DATE" "$PACKAGE_NAME")" ]]; then
      echo "$PACKAGE_NAME" >> /tmp/old_packages.txt
    fi
  fi
done < "$TEMP_FILE"

# Sort and deduplicate the package list
sort -u /tmp/old_packages.txt > /tmp/unique_old_packages.txt

# List old packages to review
echo "Old unused packages that haven't been used since $PERIOD:"
cat /tmp/unique_old_packages.txt

# Optionally, remove old packages
read -p "Do you want to remove these packages? (y/n): " CONFIRM
if [[ "$CONFIRM" == "y" ]]; then
  while IFS= read -r package; do
    sudo apt-get remove --purge -y "$package"
  done < /tmp/unique_old_packages.txt
fi

# Clean up temporary files
rm "$TEMP_FILE" /tmp/old_packages.txt /tmp/unique_old_packages.txt

echo "Cleanup complete."
