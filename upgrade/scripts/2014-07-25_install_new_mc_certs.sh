#!/bin/sh

sudo cp /opt/openmanage/upgrade/keys/server.* /var/lib/openmanage/

sudo service nginx restart
