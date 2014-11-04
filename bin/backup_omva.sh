#!/bin/bash

# Backup script for the OpenManage Virtual Appliance.

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

. /etc/default/openmanage

BACKUP_HASH_FILE=$OPENMANAGE_ROOT/.backup_hashes

lock() {
    exec 200>/var/lock/.myscript.exclusivelock

    flock -n 200 \
        && return 0 \
        || return 1
}

eexit() {
    local error_str="$@"

    echo $error_str
    exit 1
}

set_current_values() {
    md5=($(md5sum $OPENMANAGE_ROOT/etc/agent_config.json))
    echo "export AGENT_CONFIG_MD5=$md5" > $BACKUP_HASH_FILE
    md5=($(echo "select datname, tup_inserted, tup_updated, tup_deleted from pg_stat_database where datname='openmanage';" | sudo -u postgres psql openmanage | md5sum))
    echo "export DB_MD5=$md5" >> $BACKUP_HASH_FILE
}

need_backup() {
    if ! [ -a $BACKUP_HASH_FILE ] 
    then
        set_current_values
        echo "Backup needed."
        return 0
    fi
    . $BACKUP_HASH_FILE
    md5=($(md5sum $OPENMANAGE_ROOT/etc/agent_config.json))
    if [ $AGENT_CONFIG_MD5 != $md5 ]
    then
        echo "agent_config doesn't match last backup. Backup needed."
        return 0
    fi
    md5=($(echo "select datname, tup_inserted, tup_updated, tup_deleted from pg_stat_database where datname='openmanage';" | sudo -u postgres psql openmanage | md5sum))
    if [ $DB_MD5 != $md5 ]
    then
        echo "Database doesn't match last backup. Backup needed."
        return 0
    fi
    return 1
}

main() {
    lock || eexit "Script is already running. Exiting..."
    need_backup || eexit "Nothing has changed since last backup. Exiting..."
    number=$(( ( RANDOM % 45 ) + 1 ))
    echo "sleeping for $number minutes to spread out backups"
    sleep ${number}m
    set_current_values
    python $OPENMANAGE_ROOT/bin/update_backup.py
}
main
