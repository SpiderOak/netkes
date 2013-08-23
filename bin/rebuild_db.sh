#!/bin/bash

. /etc/default/openmanage

python $OPENMANAGE_ROOT/bin/directory_agent_main.py --rebuild-db
