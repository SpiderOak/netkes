#!/bin/bash
# Create backup status csv

. /etc/default/openmanage

pushd $OPENMANAGE_DJANGO_ROOT/omva
python manage.py backupstatus
popd
