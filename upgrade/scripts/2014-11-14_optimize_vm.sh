#!/bin/sh

. /etc/default/openmanage

apt-get -y remove mlocate
apt-get -y remove popularity-contest

rm /etc/cron.daily/mlocate
rm /etc/cron.daily/popularity-contest

rm /etc/crontab

ln -s $OPENMANAGE_ROOT/etc/crontab /etc/crontab
