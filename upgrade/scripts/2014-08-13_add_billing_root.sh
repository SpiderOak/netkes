#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 

python /opt/openmanage/upgrade/scripts/2014-08-13_add_billing_root.py
