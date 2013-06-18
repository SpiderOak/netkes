#!/bin/bash

# Setup web services
chroot $1 pip install gunicorn
chroot $1 pip install django-pgsql-interval-field
chroot $1 pip install django-pagination
chroot $1 pip install IPy
chroot $1 chmod a+x /opt/openmanage/django/setup_git.sh
chroot $1 /opt/openmanage/django/setup_git.sh

chroot $1 mkdir -p /etc/service/admin_console/supervise
chroot $1 ln -s /opt/openmanage/etc/service/admin_console/run /etc/service/admin_console/run

# Setup openmanage services
chroot $1 ln -s /opt/openmanage/etc/openmanage_defaults /etc/default/openmanage
chroot $1 mkdir -p /var/lib/openmanage/log
chroot $1 mkdir -p /var/lib/openmanage/layers
chroot $1 mkdir -p /var/lib/openmanage/keys

# Tweak the DB setup to run on the machine
chroot $1 sed -i "s/max_connections = /max_connections = 20 #/" /etc/postgresql/8.4/main/postgresql.conf

# Update fstab
chroot $1 sed -i "s/\/dev\/sda1/LABEL='root_disk'/" /etc/fstab
chroot $1 sed -i "s/\/dev\/sda2/LABEL='swap'/" /etc/fstab
