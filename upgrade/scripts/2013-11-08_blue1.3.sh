#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 
python /opt/openmanage/django/apps/blue_management/blue_mgnt/permissions.py

python /opt/openmanage/django/omva/manage.py syncdb --noinput
