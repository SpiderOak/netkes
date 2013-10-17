Web Management Console
======================

Your management vm includes a web-based management console to control your account. While you currently have to ssh into your management vm occaisionally, the goal is for it to be possible to do everything through this console. It allows you to import users from your ldap, view detailed information about your users, add additional admins, view logs, configure settings, etc.

Groups
******

The place to start is groups. You need groups to import your users into your management vm. All users in the group will have the same plan. If you eventually need more space for certain users you add bonus GB in the user detail page. The LDAP DN is an ldap group or ou containing some of your users. All users in that group will have spideroak accounts created for them.

Users
*****

This page gives you a high level overview of your users. Follow the login link to view files or the detail link to view more information about a specific user.

User Detail
***********

View everything about one user. Also this is where you add bonus GB. If most users of a group need 20 GB, but you have one who needs 50 GB you can give that one user 30 bonus GB.

Shares
******

View all shares for your company. Here you can view shares and disable shares individually or company wide.

Auth Codes
**********

The tokens created here can be used in place of a password. This lets you script automatic deployments without needing each user to install spideroak themselves. Codes are for a limited time and can be disabled.

Admin Groups
************

This allows you to give permissions to some or all of the management console to some of your users. Set the LDAP DN and the permissions and all users in that group or ou will be able to log into the management console with their ldap credentials. 

Logs
****

Most actions are logged. We log when something is added, modified, or deleted. The user who performed the action. And when possible we log what was changed. Here you can view and search all of these logs. 

Settings
********

Company wide preferences. Also some administrative functions for the management vm.


