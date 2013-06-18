Subscription Configuration and Management
=========================================

The SpiderOak-facing components of your OpenManage system are managed through the `SpiderOak Partners Console <https://spideroak.com/partners/>`_ .  You can login through the login and password provided to you during your SpiderOak Blue subscription setup.

.. note::

    The login used for the Partners Console is the same as the password required for the API access mentioned at :ref:`common_configuration`

General Setup
*************

There are three general configuration options, enterprise-wide:

 * ``Default share ttl``: Sets the time-to-live (TTL) for share links
 * ``Default autopurge``: Sets the autopurge time from the clients within your enterprise.
 * ``NetKES server URL``: URL for your OMVA that can be reached from SpiderOak, used for authentication.

Groups
******

Groups have the following properties:
 * ``Group ID``: Unique identifier for your group, used in configuring directory access (if used) at :ref:`group_configuration`.
 * ``Plan``: Storage plan made available to users in the group.
 * ``Allow WebAPI``: Allows mobile and web access for users in the group.
 * ``Require Domain for Windows Install``: If enabled, forces all SpiderOak installations for members of the group to belong to your Windows domain.
 * ``Delete Group``: When checked during editing, this will delete the group.
