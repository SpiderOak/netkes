
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


What's In this Repo
===================

- django: the webapp (for the management console, which let's
  enterprises manage their users, largely by interacting with accounts
  api)
- netkes: the cron job sync logic and the
  webapp that provides key (cron job is
  `run_openmanage.sh`)
  escrow services to the spideroak storage backend so that it can
  validate logins to the web and from new/reinstalled clients.
- delpoy: code to create a package to deploy this to virtual appliances
  (not sure if still used?)
- etc: key item is ```agent_config.json.sample``` - a sample configuration file for (the web management console, the cron job for ldap sync, and the key escrow service)
- sql: schema for the local postgres database (synced ldap info and/or local (non-ldap) users )
- upgrade: auto upgrade system for upgrading in place remotely deployed
  OVMA's.
