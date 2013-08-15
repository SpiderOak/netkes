#!/bin/sh

cat >> /tmp/rotate.om <<__EOF__
/var/lib/openmanage/log/directory_agent {
 rotate 10
 weekly
 compress
 missingok
 notifempty
} 
__EOF__

install /tmp/rotate.om /etc/logrotated/openmanage
rm /tmp/rotate.om
