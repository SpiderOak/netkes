#!/bin/bash

if [ -e ~/.ran_firstlogin ]; then
    exit 0
fi

. /etc/default/openmanage

sudo dpkg-reconfigure tzdata

# Setup the NetKES escrow keys.
if [ ! -f /var/lib/openmanage/keys/base.cfg ]; then
$OPENMANAGE_ROOT/bin/make_keys.sh $OPENMANAGE_BRAND
fi

touch ~/.ran_firstlogin

echo "PATH=$OPENMANAGE_ROOT/bin:\$PATH" >> ~/.bashrc

echo "Great, all done!

To setup the directory agent, please configure your settings, and then run
'finish_setup.sh' to start services.

Please see the documentation for more detail.

"
