#!/bin/bash

# Symlink logrotate config and manually kick off rotation

. /etc/default/openmanage

sudo rm /etc/logrotate.d/directory_agent
sudo ln -s $OPENMANAGE_ROOT/etc/log_rotate_directory_agent /etc/logrotate.d/directory_agent

sudo logrotate -f /etc/logrotate.d/directory_agent
