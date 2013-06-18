#!/bin/bash
# Openmanage service finalization script.
# Running this will start your services, so make sure you're configured!
# (c) 2011 SpiderOak, Inc.

. /etc/default/openmanage

if [ -e $OPENMANAGE_ROOT/netkes/account_mgr/user_source ]; then
    sudo ln -s $OPENMANAGE_ROOT/bin/run_openmanage.sh /etc/cron.hourly/run_openmanage || exit 1
fi

sudo mkdir -p /etc/service/openmanage/supervise
sudo ln -s $OPENMANAGE_ROOT/etc/service/openmanage/run /etc/service/openmanage/run
sudo sv start openmanage

if [ -e $OPENMANAGE_ROOT/netkes/account_mgr/user_source/ldap_source.py ]; then
    echo "Now we're going to start the initial LDAP->SpiderOak account sync.
This may take a while.
"
    sudo $OPENMANAGE_ROOT/bin/run_openmanage.sh
fi

