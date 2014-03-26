#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 

python /opt/openmanage/upgrade/scripts/2014-02-19_add_config_items.py
