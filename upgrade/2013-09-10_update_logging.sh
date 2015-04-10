#!/bin/bash

# Configure logging on pre-existing OMVAs to match The New Way.
# Code here modeled after the creation script.

set -e
set -x
set -o pipefail

. /etc/default/openmanage

# Setup new logging directories.
mkdir -p /var/log/omva/directory_agent
mkdir -p /var/log/omva/admin_console
mkdir -p /var/log/omva/openmanage

for SERVICE in openmanage admin_console; do
    mkdir -p /etc/service/$SERVICE/log

    if [ ! -f /etc/service/$SERVICE/log/run ]; then
        # Install logging handlers
        cat > /tmp/logrun.$SERVICE <<EOF
#!/bin/bash
. /etc/default/openmanage
LOGDIR=\$OPENMANAGE_LOGS/$SERVICE
mkdir -p \$LOGDIR
exec svlogd \$LOGDIR
EOF
        install -D -m 755 /tmp/logrun.$SERVICE /etc/service/$SERVICE/log/run
    fi
done

sv e openmanage admin_console

# Archive the old logging data.
tar cjfv /home/openmanage/oldlogs.tar.bz2 /var/lib/openmanage/log
