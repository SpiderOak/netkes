#!/bin/sh

install -d /var/log/omva/directory_agent
cd /var/lib/openmanage
mv log/* /var/log/omva/directory_agent
rm log
ln -s /var/log/omva/directory_agent log
