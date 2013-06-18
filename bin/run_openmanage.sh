#!/bin/bash
# Openmanage run script for cron.
# openmanage cron hourly

. /etc/default/openmanage

python $OPENMANAGE_ROOT/bin/directory_agent_main.py
