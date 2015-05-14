#!/bin/sh

. /etc/default/openmanage
PYTHONPATH=/opt/openmanage/django:$PYTHONPATH 

python /opt/openmanage/upgrade/scripts/2015-03-30_add_send_activation_email.py
