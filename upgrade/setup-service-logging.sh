#!/bin/sh

sv stop admin_console openmanage
rm -rf /etc/service/openmanage /etc/service/admin_console
install -d /var/log/omva
# Run scripts:
for SERVICE in openmanage admin_console
do
	cat > /tmp/logrun.$SERVICE <<__EOF__
#!/bin/bash

if [ ! -d /var/log/omva/$SERVICE ]; then mkdir /var/log/omva/$SERVICE; fi

exec svlogd /var/log/omva/$SERVICE
__EOF__
	# This next step a) creates the service directory, b) creates a valid log
	# directory, and c) installs the log/run file all in one fell swoop.  This
	# allows runsvdir to detect the new service directory and walk it, creating
	# the supervisor dirs and creates service handlers for each.
	install -D -m 755 /tmp/logrun.$SERVICE /etc/service/$SERVICE/log/run
	cd /etc/service/$SERVICE
	ln -s /opt/openmanage/etc/service/$SERVICE/run
done
sv start admin_console openmanage
rm /tmp/logrun.*
