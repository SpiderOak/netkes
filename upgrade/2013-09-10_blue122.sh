#!/bin/bash

# One-off upgrade script for OMVAs.  We expect this script to be run
# via sudo, and the rest of the update directory available at this
# level.

set -x
set -e
set -o pipefail

. /etc/default/openmanage

UPDATE_TARBALL=${1:?}

# Stop services.
for SERVICE in admin_console openmanage; do
    sv down $SERVICE || (echo "Unable to stop $SERVICE" ; exit)
done

# Move out old openmanage
mv /opt/openmanage /opt/openmanage.122old

pushd /opt/openmanage
tar xjfv $UPDATE_TARBALL
popd #/opt/openmanage

# Update logging configuration
./2013-09-10_update_logging.sh

# Determine if we need to update the database with new schema.
if [ ! $(su postgres -c 'psql -c "\d sql_updates" openmanage') ]; then
    su postgres -f $OPENMANAGE_ROOT/sql/2013-04-02_manage_sql_updates.sql
fi

# Bring over configuration into the new stuff.
cp /opt/openmanage.122old/etc/agent_config.json /opt/openmanage/etc
grep 'DJANGO_SECRET_KEY' /opt/openmanage.122old/etc/openmanage_defaults >> /opt/openmanage/etc/openmanage_defaults

# Restart services
for SERVICE in openmanage admin_console; do
    sv up $SERVICE
done
