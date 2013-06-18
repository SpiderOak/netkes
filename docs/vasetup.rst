OMVA Setup
==========

The OMVA is a virtual machine with the following base requirements:

 * 512 MB RAM
 * 5 GB HDD
 * 1 Network address

Network Access
**************

The OMVA needs to be able to connect to and accept connections from your SpiderOak Blue storage to function. Your firewall and proxy configuration around the OMVA will need to be configured to permit connections to and from your storage. We have provided a table you can use as a worksheet to reference if a Blue Hosted Storage customer, or fill in and then reference as a Private Cloud customer.

+-----------------+----------+-----------------------------------+-------------------------+
| Protocol        | In / Out | Hosted Storage                    | Private Cloud           |
+=================+==========+===================================+=========================+
| HTTPS (443)     | out      | ``spideroak.com`` (208.28.15.128) |                         |
+-----------------+----------+-----------------------------------+-------------------------+
| HTTPS (443)     | in       | | 208.28.15.128                   |                         |
|                 |          | | 208.28.15.131                   | (only 1 IP necessary)   |
|                 |          | | 38.121.104.4                    |                         |
|                 |          | | 38.121.104.5                    |                         |
+-----------------+----------+-----------------------------------+-------------------------+

In addition, the following ports are necessary to be kept open locally for administrative purposes:

* HTTPS (port 443) IN (Web management console)
* SSH (port 22) IN (Command-line management)

Finally, you will need to connect to your directory server:

* LDAP/LDAPS to your directory server.

The OMVA is configured to get its network address through DHCP.  Please contact SpiderOak if you require a virtual machine with a pre-configured IP address.

There are two SSL configurations possible behind a proxy with the OMVA.  The virtual appliance ships with its own self-signed certificate that SpiderOak will optionally validate lacking the presence of a conventional SSL certificate signed by a CA.  This provides flexibility to position the OMVA within your infrastructure behind proxies (or not) as desired.

Lastly, if using directory integration, you will need a user account in the directory with access rights to read the groups you are defining to hold SpiderOak-enabled users.

.. note::

    For more information concerning directory integration, please see :doc:`ldap`

The current version of the machine is running Ubuntu 10.04 LTS in a
stripped-down configuration.  To retreive updates to the OS, you will either have to enable outbound HTTP access to ``archive.ubuntu.com`` and ``security.ubuntu.com`` or configure the OMVA's apt to use a local mirror or proxy.


Initial Installation
********************

Upon initial boot, the system will configure itself, including creating encryption escrow keys, generating fresh OpenSSH keys, and presenting you with a login prompt.  The default login credentials are:

* username: ``openmanage``
* password: ``openmanage``

With the initial login, a script will guide you through changing your admin password and the DB user password.

Once logged in, please configure the services on the machine for your use.  A sample configuration script is included at ``/opt/openmanage/etc/agent_config.json.sample``.  This is a JSON-format file with sample (and it should be noted, incorrect!) values to access your local directory, your SpiderOak administrative account, and the password you set for the local database.  In addition, the sample file includes definitions for sample directory groups.

The JSON configuration file should be named ``/opt/openmanage/etc/agent_config.json``. Once that is configured, run ``finish_setup.sh`` from the command prompt.  The configuration will finish, and the system services will start along with an initial directory to SpiderOak account sync (for accounts with that feature).


Configuration File Options
**************************

The configuration file is a simple JSON-format file at ``/opt/openmanage/etc/agent_config.json``.  There is a sample configuration file included with the OMVA at ``/opt/openmanage/etc/agent_config.json.sample`` that can be copied to the actual name and then edited to setup the initial configuration.

.. _common_configuration:

Common Configuration Options
++++++++++++++++++++++++++++

* ``api_user``: The administrative user for your SpiderOak Blue subscription.  This is the same as the user you use to login to the web admin console on the SpiderOak website.
* ``api_password``: The password for the administrative user's account.
* ``api_root``: The URL to connect to the Billing API for your storage backend. **NOTE:** This option is internally configured properly by default for Blue Hosted Storage. You only need to introduce this variable for Blue Private Cloud.
* ``db_pass``: The password you've chosen for the database access.
* ``listen_addr``: The IP address for the NetKES to listen on.  This should be the IP address configured for the OMVA.
* ``listen_port``: The port for the OMVA to listen on.  The default of 443 (HTTPS) is a reasonable sane default.

.. _ldap_configuration:

LDAP Configuration Options
+++++++++++++++++++++++++++++++

.. note::
    For more information concerning directory integration, please see :doc:`ldap`

OpenManage's directory integration features are based around the Lightweight Directory Access Protocol (LDAP).  As Microsoft Active Directory is a form of LDAP, we use LDAP conventions when referring to AD.  Mapping AD concepts to LDAP terms is simple but generally beyond the scope of this documentation; the source defaults in the sample configuration file are geared towards the default AD LDAP schema, but can be changed to suit your requirements.

* ``dir_uri``: This should reflect the LDAP URI to connect to, in the form of ``<protocol>://<hostname>[:<port>]``. ``<protocol>`` is either ``ldap`` or ``ldaps``, depending on use of SSL for your LDAP connection.
* ``dir_base_dn``: The base DN in the LDAP tree to run searches against.  In the case of the sample, this simply searches against the entire domain for test.domain.com.  To restrict it to the top-level Users OU, for example, it would then be ``cn=Users, dc=test, dc=domain, dc=com``. Leaving this set at too high of a level (say, ``dc=test, dc=domain, dc=com``) may negatively impact performance searching through too many not useful objects.
* ``dir_type``: The type of LDAP installation you have, either ``posix`` for OpenLDAP and RedHat Directory Server, or ``ad`` for Microsoft Active Directory.
* ``dir_user``: The user account created to give the directory agent access to read the group membership.
* ``dir_password``: The password for the above user account.
* ``dir_guid_source``: Field name for user objects defining a UID that will not change for the life of the object.  This is used to track user objects through name changes and group reassignments.  The sample provides the MS AD UID field.  If using AD, this should not need to be changed.  For other LDAP implementations, please use whatever field name is used by your implementation.
* ``dir_fname_source``: Source for the personal name in the LDAP schema.  The default given is for AD.
* ``dir_lname_source``: Source for the surname in the LDAP schema.  The default given is for AD.
* ``dir_username_source``: Source for the unique username in the LDAP schema.  The default given is for AD, which in simple cases will suffice.  If the user's email address is represented in the directory, we recommend that as well as a suitable field.
* ``auth_method``: Source for authentication. Either ``ldap`` for LDAP-bind authentication, or ``radius`` for RADIUS authentication.

.. note::
    See :doc:`ldap` or :doc:`radius` for details on LDAP and RADIUS authentication.

RADIUS Configuration Options
++++++++++++++++++++++++++++

.. note::
    For more information concerning RADIUS authentication, please see :doc:`radius`.


* ``rad_server``: The RADIUS server to connect to.
* ``rad_secret``: The shared RADIUS secret.
* ``rad_dictionary``: The RADIUS dictionary.

Group Configuration
-------------------

The ``groups`` member in the configuration is special.  Please leave the blank group configuration from the sample, as this will be populated from the :doc:`managementconsole`. Entries in this section are considered internal to the software.

Post Setup
**********

After running ``finish_setup.sh``, the OMVA should 'just work' with little to no administrative interaction from there.  However, we recommend that a backup be made of your key escrow keys.  If the KES keys are lost, **all user accounts will have to be reset from scratch!** This is obviously a bad thing.  We *highly* recommend that backups of the KES keys be made.  They can be found at ``/var/lib/openmanage/keys`` and ``/var/lib/openmanage/layers``.  We recommend making a backup of those directories and storing them somewhere safe and secure.

.. warning::
    Backup your escrow keys as above; in the event of failure, **YOU WILL NOT BE ABLE TO RECOVER YOUR DATA**.

In a near-future release, backup tools will be made available as part of the OMVA toolset.
