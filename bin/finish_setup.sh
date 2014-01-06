#!/bin/bash
# Openmanage service finalization script.
# Running this will start your services, so make sure you're configured!
# (c) 2011 SpiderOak, Inc.

. /etc/default/openmanage

if [ -e $OPENMANAGE_ROOT/netkes/account_mgr/user_source/ldap_source.py ]; then
    echo "Now we're going to start the initial LDAP->SpiderOak account sync.
This may take a while.
"
    sudo $OPENMANAGE_ROOT/bin/run_openmanage.sh
fi

