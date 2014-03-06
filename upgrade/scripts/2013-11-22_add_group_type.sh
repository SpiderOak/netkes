#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 

python /opt/openmanage/upgrade/scripts/2013-11-22_add_group_type.py
