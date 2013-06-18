#!/bin/bash

. /etc/default/openmanage

python $OPENMANAGE_ROOT/netkes/key_escrow/admin.py create_base
python $OPENMANAGE_ROOT/netkes/key_escrow/admin.py setup_brand $1
