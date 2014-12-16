#!/bin/sh

. /etc/default/openmanage

sudo rm /etc/cron.hourly/backup_omva*
sudo ln -s $OPENMANAGE_ROOT/bin/backup_omva.sh /etc/cron.hourly/backup_omva
