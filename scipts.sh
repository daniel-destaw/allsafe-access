#!/bin/bash
# This script automatically generates the debian/install file by
# verifying that the source paths exist after the build process.

# Define an associative array for the source and destination paths.
# This makes it easy to add or remove files as your project changes.
# The format is "source_path": "destination_path"
declare -A install_map
install_map=(
    # Binaries
    ["bin/allsafe-proxy"]="usr/bin/"
    ["bin/allsafe-cli"]="usr/bin/"
    ["bin/allsafe-agent"]="usr/bin/"
    ["bin/allsafe-admin"]="usr/bin/"
    ["bin/allsafe-auth"]="usr/bin/"

    # Proxy templates
    ["cmd/allsafe-proxy/templates/*"]="usr/share/allsafe-proxy/templates/"

    # Proxy configs & certs
    # The '*' wildcard is used here to copy all files within the directory.
    ["configs/configs/allsafeproxy/*"]="etc/allsafe-proxy/"
    ["configs/certs/proxy.crt"]="etc/allsafe-proxy/certs/"
    ["configs/certs/proxy.key"]="etc/allsafe-proxy/certs/"
    ["configs/certs/proxy_ca.crt"]="etc/allsafe-proxy/certs/"

    # Agent configs & certs
    ["configs/configs/allsafeagent/*"]="etc/allsafe-agent/"
    ["configs/certs/agent.crt"]="etc/allsafe-agent/certs/"
    ["configs/certs/agent.key"]="etc/allsafe-agent/certs/"
    ["configs/certs/agent_ca.crt"]="etc/allsafe-agent/certs/"

    # CLI configs
    ["configs/configs/allsafecli/*"]="etc/allsafe-cli/"

    # Roles
    ["configs/roles/*"]="etc/allsafe-access/role/"
)

# Create a temporary file to write the new debian/install content.
temp_install_file=$(mktemp)

echo "Generating debian/install file..."

# Iterate over the associative array to check each path
for source_path in "${!install_map[@]}"; do
    destination_path="${install_map[$source_path]}"
    
    # Check if the path contains a wildcard
    if [[ "$source_path" == *'*'* ]]; then
        # If it has a wildcard, check if the parent directory exists
        parent_dir="${source_path%/*}"
        if [ -d "$parent_dir" ]; then
            # The parent directory exists, so we assume the wildcard is valid
            echo "$source_path $destination_path" >> "$temp_install_file"
            echo "  ✅ Found and added: $source_path (via wildcard check)"
        else
            # The parent directory does not exist, so the path is invalid
            echo "  ⚠️  Warning: Parent directory not found for wildcard path: $parent_dir"
        fi
    else
        # No wildcard, so just check if the file or directory exists
        if [ -e "$source_path" ]; then
            echo "$source_path $destination_path" >> "$temp_install_file"
            echo "  ✅ Found and added: $source_path"
        else
            echo "  ⚠️  Warning: Source path not found: $source_path"
        fi
    fi
done

# Overwrite the existing debian/install file with the new content
cp "$temp_install_file" "debian/install"

# Clean up the temporary file
rm "$temp_install_file"

echo "Done! The new debian/install file has been created successfully."
echo "Please inspect debian/install to ensure it meets your expectations."
