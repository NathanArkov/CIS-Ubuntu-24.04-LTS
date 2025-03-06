#!/bin/bash

# Check if /tmp is mounted without the noexec option
if findmnt -kn /tmp | grep -v noexec; then
    echo "/tmp is mounted without the noexec option. Remediation needed"
else
    echo "/tmp is mounted with the noexec option."
fi