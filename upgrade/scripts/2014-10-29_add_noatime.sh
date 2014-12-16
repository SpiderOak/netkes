#!/bin/sh

sed -i 's/errors=remount-ro/errors=remount-ro,noatime/' /etc/fstab
