#!/bin/bash

# Check if /tmp is mounted without the nodev option
if findmnt -kn /tmp | grep -v nodev; then
    echo "/tmp is mounted without the nodev option. Remediation needed"
else
    echo "/tmp is mounted with the nodev option."
fi