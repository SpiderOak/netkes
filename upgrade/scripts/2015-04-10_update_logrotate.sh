#!/bin/bash

# Configure directory_agent to roate on size

set -e
set -x
set -o pipefail

LOGCONF='/etc/logrotate.d/directory_agent'
ROTMP='/tmp/rotate.om'

# Create directory_agent logrotate config or
# replace if not using size based rotation.

if [ ! -f $LOGCONF ] || ! grep -q size "$LOGCONF"; then
	cat > $ROTMP <<EOF
/var/log/omva/directory_agent {
  rotate 4
  size 500M
  compress
  missingok
  notifyempty
}
EOF
	install $ROTMP $LOGCONF
	rm $ROTMP
fi
