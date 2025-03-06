#!/bin/bash

# Check if /tmp is mounted without the nosuid option
if findmnt -kn /tmp | grep -v nosuid; then
    echo "/tmp is mounted without the nosuid option. Remediation needed"
else
    echo "/tmp is mounted with the nosuid option."
fi