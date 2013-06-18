#!/bin/bash

tries=0
while [ $tries -le 2 ]; do
    stty -echo
    read -p "New SQL password: " firstpw; echo
    read -p "New SQL password (again): " secondpw; echo
    stty echo

    if [ $firstpw = $secondpw ]; then
        break
    fi
    tries=$(( $tries + 1 ))
    echo "Passwords did not match, try again."
done

if [ $tries -eq 3 ]; then
    echo "Too many tries, giving up!"
    exit 1
fi

psql -h localhost -U directory_agent openmanage -c "alter role directory_agent with password '$firstpw';"
