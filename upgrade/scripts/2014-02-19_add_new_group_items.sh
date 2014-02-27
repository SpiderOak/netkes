#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 

python /home/openmanage/netkes/upgrade/scripts/2014-02-19_add_new_group_items.py
