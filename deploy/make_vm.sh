#!/bin/bash

# Builds a SO OMVA.

if [ $# -eq 0 ]; then
    echo "I need a hypervisor!"
    exit
fi

netfile=`pwd`/network-$2
if [ -e $netfile ]; then
    echo 'network settings:'
    netsettings=`cat $netfile`
    echo $netsettings
    echo ''
else
    netsettings=''
fi

firstboot=`pwd`/firstboot.sh
execscript=`pwd`/postinstall.sh

./make_tarball.sh .. $1 $2 $4

sudo vmbuilder $3 ubuntu --verbose --debug -c omva_vmbuilder.conf -o --firstboot $firstboot --execscript $execscript $netsettings -d $2_$3 --part vmbuilder.partition

# echo "sleeping between steps..."
# sleep 10
# mv $DESTDIR openmanage-$2-$3
# echo "sleeping between steps..."
# sleep 10

# which pgiz > /dev/null
# if [ $? -eq 0 ]; then
# our_gzip=pigz
# else
# our_gzip=gzip
# fi

# tar cf - openmanage-$2-$3/ | $our_gzip > openmanage-$2-$3.tar.gz
