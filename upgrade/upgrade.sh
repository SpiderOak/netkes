#!/bin/bash

# Standard  upgrade script for OMVAs.  We expect this script to be run
# via sudo.

if [ "$(id -u)" != "0" ]; then
    echo "Please run via sudo"
    exit 1
fi

set -x
set -e
set -o pipefail

. /etc/default/openmanage

UPDATE_TARBALL=${1:? "Update tarball is undefined"}
BRAND=${2:?    "Brand is underfined!"}

CURRENT_DATE=$(date "+%y-%m-%d")


# Stop services.
for SERVICE in admin_console openmanage; do
    sv down $SERVICE || (echo "Unable to stop $SERVICE" ; exit)
done

# Move out old openmanage
mv /opt/openmanage /opt/openmanage.$CURRENT_DATE

pushd /opt
tar xjfv $UPDATE_TARBALL
popd #/opt

# Bring over configuration into the new stuff.
cp /opt/openmanage.$CURRENT_DATE/etc/agent_config.json /opt/openmanage/etc
grep 'DJANGO_SECRET_KEY' /opt/openmanage.$CURRENT_DATE/etc/openmanage_defaults >> /opt/openmanage/etc/openmanage_defaults 

# Set the brand in the configuration
echo "OPENMANAGE_BRAND=$BRAND" > /opt/openmanage/etc/brand

echo "about to apply"
PYTHONPATH=/opt/openmanage python /home/openmanage/openmanage/upgrade/apply_sql.py
PYTHONPATH=/opt/openmanage python /home/openmanage/openmanage/upgrade/apply_scripts.py
echo "applied"

# Restart services
for SERVICE in openmanage admin_console; do
    sv up $SERVICE
done

echo "Upgrade complete!"
