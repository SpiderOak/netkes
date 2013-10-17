# 1.3

## New Features

### Multiple Admins

We now provide support for multiple admins. Access to most actions in the management console are controlled by permissions. The account that's been used so far is the superuser and has all permissions. You can now create admin groups. An admin group is an LDAP dn and a set of permissions. All users that match that LDAP dn will be able to log in using their LDAP credentials and access the parts of the site they have permissions to access.

### Log Interface

Most actions are now logged. We log when something is added, modified, or deleted. The user who performed the action. And when possible we log what was changed. These logs are visible in the logs tab.
