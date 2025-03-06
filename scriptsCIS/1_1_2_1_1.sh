#!/usr/bin/env bash

if [[ -n $(findmnt -kn /tmp) && ("$status" != "masked" && "$status" != "disabled") ]]; then
    echo -e "\e[0;32m Le montage de /tmp est correctement configuré. \e[0m"
else
    echo -e "\e[0;31m Le montage de /tmp n'est pas correctement configuré. Le montage de /tmp est soit masqué soit désactivé \e[0m"
fi