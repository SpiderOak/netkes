#!/bin/sh

. /etc/default/openmanage

sudo rm /etc/nginx/sites-available/default
sudo ln -s $OPENMANAGE_ROOT/etc/nginx_vhost /etc/nginx/sites-available/default

sudo service nginx restart
