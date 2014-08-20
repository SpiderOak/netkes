#!/bin/bash

# Backup script for the OpenManage Virtual Appliance.

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

. /etc/default/openmanage

BACKUP_BASE=$OPENMANAGE_ROOT/tmp_backup

rm -rf $BACKUP_BASE
mkdir $BACKUP_BASE

python $OPENMANAGE_ROOT/bin/restore_backup.py
