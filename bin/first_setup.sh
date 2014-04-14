#!/bin/bash

if [ -e ~/.ran_firstsetup ]; then
    exit 0
fi

. /etc/default/openmanage

OPENMANAGE_BRAND=$1

echo "creating keys"

# Setup the NetKES escrow keys.
if [ ! -f /var/lib/openmanage/keys/base.cfg ]; then
$OPENMANAGE_ROOT/bin/make_keys.sh $OPENMANAGE_BRAND
fi

#sudo mkdir -p /etc/service/openmanage/supervise
#sudo ln -s $OPENMANAGE_ROOT/etc/service/openmanage/run /etc/service/openmanage/run
#sudo sv start openmanage

touch ~/.ran_firstsetup

echo "finished"
