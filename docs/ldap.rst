Directory Integration
=====================

OMVA supports connecting to your organization's user directory and automatically configuring SpiderOak user accounts for members of your organization, as well as using your directory to authenticate users.

OpenManage supports the Lightweight Directory Access Protocol (LDAP).  This is an open industry-wide standard, supported by Microsoft, Apple, Novell, and the open source community.

LDAP integration is accomplished by reading the member list of groups defined in the configuration file, matching them to the SpiderOak user database, and resolving differences.  The implementation internally uses a SQL database to assist in resolving the user DB differences and tracking the matching between the LDAP user object and user entries in the SpiderOak database.

Active Directory
****************

As Microsoft Active Directory is a superset of LDAP, OpenManage communicates with it via standard LDAP methods.  Your AD must be configured properly, and to configure OpenManage, you must have some understanding of LDAP.  You can browse your AD via Microsoft's ``ldp.exe`` tool (included with Windows Server), or the extended attributes on AD objects when turned on through the MMC settings for *Active Directory Users and Computers*.

Setup
*****

OpenManage works by examining the members of user groups in LDAP.  Each LDAP group correlates to a group setup through the SpiderOak Blue :ref:`managementconsole`, using internally-held data to connect a SpiderOak Blue user group to your LDAP group.

.. note::
    See :ref:`ldap_configuration` for more information on how to configure the OMVA to connect to your LDAP server.

The OpenManage LDAP user will need to be able to read the member list of the group, as well as read the attributes of the user objects.  No write permissions are necessary, and should be avoided for security reasons.

