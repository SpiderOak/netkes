#!/bin/sh

test -f /etc/logrotate.d/openmanage && exit

echo "Setting up log rotation for directory_agent..."
cat >> /tmp/rotate.om <<__EOF__
/var/lib/openmanage/log/directory_agent {
 rotate 10
 weekly
 compress
 missingok
 notifempty
} 
__EOF__

install /tmp/rotate.om /etc/logrotate.d/openmanage
rm /tmp/rotate.om
