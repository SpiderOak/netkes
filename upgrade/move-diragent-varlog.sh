#!/bin/sh

test -h /var/lib/openmanage/log && exit
echo Creating new log directory...
install -d /var/log/omva/directory_agent
cd /var/lib/openmanage
mv log/* /var/log/omva/directory_agent
rmdir log
ln -s /var/log/omva/directory_agent log
