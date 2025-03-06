#!/usr/bin/env bash

# Function to run all scripts in a directory
run_scripts() {
    local dir=$1
    for script in "$dir"/*.sh; do
        if [ -f "$script" ]; then
            echo "Running $(basename "$script")..."
            bash "$script"
        fi
    done
}

# Prompt user for action
echo "Please select an action:"
echo "1. Audit"
echo "2. Remediate"
read -p "Enter your choice (1 or 2): " choice

# Execute based on user choice
case $choice in
    1)
        run_scripts "scriptsCIS"
        ;;
    2)
        run_scripts "remediationCIS"
        ;;
    *)
        echo "Invalid choice. Please select 1 or 2."
        exit 1
        ;;
esac