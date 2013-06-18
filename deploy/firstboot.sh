#!/bin/bash
# OpenManage initial boot setup script.

# Regenerate SSH keys.
rm /etc/ssh/ssh_host*key*
dpkg-reconfigure -fnoninteractive -pcritical openssh-server

. /etc/default/openmanage

# Setup the NetKES escrow keys.
$OPENMANAGE_ROOT/bin/make_keys.sh $OPENMANAGE_BRAND

# Install the DB.
su postgres -c "createdb openmanage"
su postgres -c "psql -f /opt/openmanage/sql/base_schema.sql openmanage"

# Setup the django project.
pushd $OPENMANAGE_DJANGO_ROOT/omva
python manage.py syncdb --noinput
python manage.py createsuperuser --noinput --username="console_admin" --email="invalid@email.act"
popd

echo "/opt/openmanage/bin/first_setup.sh" >> /home/openmanage/.bashrc
echo "PATH=$OPENMANAGE_ROOT/bin:\$PATH" >> /home/openmanage/.bashrc


