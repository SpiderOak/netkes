#!/bin/sh

. /etc/default/openmanage

sudo rm /var/lib/openmanage/server.*
sudo ln -s $OPENMANAGE_ROOT/etc/keys/server.crt /var/lib/openmanage/
sudo ln -s $OPENMANAGE_ROOT/etc/keys/server.key /var/lib/openmanage/

sudo service nginx restart
