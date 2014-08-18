#!/bin/bash

# Backup script for the OpenManage Virtual Appliance.

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

. /etc/default/openmanage

python $OPENMANAGE_ROOT/bin/restore_backup.py
