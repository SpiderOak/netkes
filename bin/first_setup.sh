#!/bin/bash

if [ -e /opt/openmanage/etc/.ran_firstsetup ]; then
    echo "Keys already generated. Exiting"
    exit 0
fi

. /etc/default/openmanage

OPENMANAGE_BRAND=$1

echo "creating keys"

# Setup the NetKES escrow keys.
if [ ! -f /var/lib/openmanage/keys/base.cfg ]; then
$OPENMANAGE_ROOT/bin/make_keys.sh $OPENMANAGE_BRAND
fi

touch /opt/openmanage/etc/.ran_firstsetup

echo "finished"
