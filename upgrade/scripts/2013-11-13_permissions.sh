#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 
python /opt/openmanage/upgrade/scripts/permissions.py
