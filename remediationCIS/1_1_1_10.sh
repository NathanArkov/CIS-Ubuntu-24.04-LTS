#!/usr/bin/env bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

        echo -e "${RED}FAIL: Remediation is manual"
        echo "Check page 72 of the CIS benchmark for detailed instructions"
        return 1

