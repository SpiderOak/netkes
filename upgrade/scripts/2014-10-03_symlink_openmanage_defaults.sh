#!/bin/sh

. /etc/default/openmanage

sudo rm /etc/default/openmanage
sudo ln -s $OPENMANAGE_ROOT/etc/openmanage_defaults /etc/default/openmanage
