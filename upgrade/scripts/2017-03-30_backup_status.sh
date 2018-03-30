#!/bin/bash

# Symlink logrotate config and run backup status daily

. /etc/default/openmanage

mkdir -p /var/log/omva/backup_status

sudo ln -s $OPENMANAGE_ROOT/etc/log_rotate_backup_status /etc/logrotate.d/backup_status
sudo ln -s $OPENMANAGE_ROOT/bin/backup_status.sh /etc/cron.daily/backup_status
