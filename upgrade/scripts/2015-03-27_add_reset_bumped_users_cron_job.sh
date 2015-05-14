#!/bin/sh

. /etc/default/openmanage

sudo ln -s $OPENMANAGE_ROOT/bin/reset_bumped_users.sh /etc/cron.hourly/reset_bumped_users
