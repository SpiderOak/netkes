[![Build Status](https://travis-ci.org/SpiderOak/netkes.svg?branch=master)](https://travis-ci.org/SpiderOak/netkes)

# The OpenManage Virtual Appliance

The OpenManage Virtual Appliance (OMVA) provides automatically managed
configuration for SpiderOak Blue&trade; services.  It provides three
major services: LDAP-driven automatic user provisioning, user
authentication to either LDAP or RADIUS servers, and encryption key
escrow management for the enterprise.

The net_kes project provides all these services for the OMVA.

## Building

The (currently clunky) way to create a deployment tarball is:

`$ ./make_tarball.sh <source_directory> <version> <brand_id> ldap`.

Where:

* `source_directory`: where to find the deployment source.
* `version`: Human-readable version number.
* `brand_id`: Enterprise brand id to build for
* `ldap`: Leave as `ldap`. Will be removed in future versions.

This will create a file called `openmanage.tar.bz2`, ready for
deployment on an OMVA.
