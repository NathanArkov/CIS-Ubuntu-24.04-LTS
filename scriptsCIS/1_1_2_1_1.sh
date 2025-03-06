#!/usr/bin/env bash

findmnt -kn /tmp;
status=$(systemctl is-enabled tmp.mount)
if [[ "$status" == "masked" || "$status" == "disabled" ]]; then
    echo -e "\e[0;31m Le montage de /tmp est soit masqué soit désactivé. \e[0m"
fi
