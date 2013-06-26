# The OpenManage Virtual Appliance

The OpenManage Virtual Appliance (OMVA) provides automatically managed configuration for SpiderOak Blue&trade; services.  It provides two major services: authentication and user management, and local encryption key escrow.

The OMVA is a virtual appliance running Linux to provide services from within your organization to SpiderOak.  By using the OMVA, SpiderOak retains our innovative zero-knowledge (Ø-K) security model concerning your organization's data while allowing you full control over both data and user account management.

Services on the OMVA:
* Communicate out to the SpiderOak Accounts API to configure and manage user accounts,
* Listen to SpiderOak for queries for key escrow use,
* Listen to SpiderOak for queries concerning user authentication.

You will be using the OMVA in one of two configurations: Blue Private Cloud, or Blue Hosted Storage. The OMVA operates largely the same between the two configurations, however the connection information will change if you are connecting to SpiderOak hosted storage or your own Private Cloud install.

See the [docs](https://github.com/SpiderOak/netkes/tree/master/docs) subdirectory for details.