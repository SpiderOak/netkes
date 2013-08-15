#!/bin/sh

set -e #-x

grep /var/log /etc/fstab  > /dev/null && echo /var/log is already on its own volume && exit

echo
echo Before running this, the new volume should me made and
echo mounted in /mnt.  If not, stop now and set that up.
echo
echo 'Continue? (yes to continue, anything else to quit.)'
read CONT
if [ $CONT != "yes" ]
then
	exit
fi
echo
echo Continuing on.  If you do not see \"FINISHED\", then the operation
echo may not have completed successfully.  Investigate the cause and
echo manually complete the operation upon failure.
echo
echo Stopping services...
service rsyslog stop
service postgresql-8.4 stop
service nginx stop
echo Moving data...
cd /var/log
mv * /mnt
cd
echo Remounting new volume...
umount /mnt
fsck /var/log
mount /var/log
echo Restarting services...
service rsyslog start
service postgresql-8.4 start
service nginx start
echo FINISHED! /var/log is now on a separate volume.
