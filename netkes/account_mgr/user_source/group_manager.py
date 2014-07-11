"""
group_manager.py

(c) 2011 SpiderOak, Inc.

Provides the group management decision making; given sets of users
from both LDAP and SpiderOak, determines the changes required to make
SpiderOak fit the LDAP groups.
"""

import logging
import psycopg2

import account_mgr
from account_mgr.user_source import ldap_source
from account_mgr import account_runner
from common import get_config

_USERS_TO_CREATE_QUERY = '''
SELECT
l.uniqueid, l.email, l.givenname, l.surname, l.group_id
FROM ldap_users l
LEFT OUTER JOIN users u ON l.uniqueid = u.uniqueid
WHERE u.uniqueid IS NULL;
'''

_USERS_TO_ENABLE_QUERY = '''
SELECT
l.uniqueid, u.avatar_id, l.email
FROM ldap_users l
LEFT OUTER JOIN users u ON l.uniqueid = u.uniqueid
WHERE u.enabled IS FALSE;
'''

_USERS_TO_DISABLE_QUERY = '''
SELECT
u.uniqueid, u.avatar_id, u.email
FROM users u
LEFT OUTER JOIN ldap_users l ON u.uniqueid = l.uniqueid
WHERE l.uniqueid IS NULL AND u.enabled IS TRUE;
'''

_USERS_TO_PLANCHANGE_QUERY = '''
SELECT
l.uniqueid, u.avatar_id, l.email, l.group_id
FROM ldap_users l
LEFT OUTER JOIN users u ON l.uniqueid = u.uniqueid
WHERE l.group_id != u.group_id;
'''

_USERS_TO_EMAILCHANGE_QUERY = '''
SELECT
l.uniqueid, u.avatar_id, l.email, u.email
FROM ldap_users l
LEFT OUTER JOIN users u ON l.uniqueid = u.uniqueid
WHERE l.email != u.email;
'''


def _process_query(db_conn, query, extras=None):
    log = logging.getLogger('_process_query')

    if extras is None:
        extras = []

    cur = db_conn.cursor()
    cur.execute(query)
    results = list()
    for row in cur.fetchall():
        userinfo = {'uniqueid' : row[0]}
        for index, extra in enumerate(extras):
            userinfo[extra] = row[index+1]
            
        if 'avatar_id' in extras:
            log.debug('Query processing avatar %d' % (userinfo['avatar_id'],))
        else:
            log.debug('Query processing avatar %s' % (userinfo['email'],))

        results.append(userinfo)

    return results

def _calculate_changes_against_db(db_conn, config, users):
    """
    Calculates the changes necessary by comparing our groups from LDAP to the DB.
    """
    log = logging.getLogger('calculate_changes')
    api_actions = dict()

    cur = db_conn.cursor()
    cur.execute("CREATE TEMPORARY TABLE ldap_users (LIKE users) ON COMMIT DROP;")
    cur.execute("ALTER TABLE ldap_users DROP COLUMN avatar_id;")
    cur.execute("ALTER TABLE ldap_users DROP COLUMN enabled;")
    if 'dir_email_source' in get_config():
        cur.executemany("INSERT INTO ldap_users (uniqueid, username, email, givenname, surname, group_id) VALUES (%(uniqueid)s, %(username)s, %(email)s, %(firstname)s, %(lastname)s, %(group_id)s);",
                    users)
    else:
        cur.executemany("INSERT INTO ldap_users (uniqueid, email, givenname, surname, group_id) VALUES (%(uniqueid)s, %(email)s, %(firstname)s, %(lastname)s, %(group_id)s);",
                    users)

    ordered_groups = sorted(config['groups'], 
                            key=lambda x: x['priority'],
                            reverse=True)

    delete_duplicate_groups = '''
    delete from ldap_users lu1 
    using ldap_users lu2
    where lu1.email = lu2.email and lu1.group_id != lu2.group_id 
        and lu1.group_id != %s
    '''

    for group in ordered_groups:
        group_id = group['group_id']
        cur.execute(delete_duplicate_groups, [group['group_id']])

    cur.execute("SELECT email, count(email) as occurences from ldap_users group by email having ( count(email) > 1 )")

    for row in cur.fetchall():
        log.error("---> Duplicate user %s found %d times in LDAP query!", row[0], row[1])

    cur.close()

    # Users to create.
    log.debug('Creating users:')
    if 'dir_email_source' in get_config():
        create_attrs = ['username', 'email', 'firstname', 'lastname', 'group_id']
    else:
        create_attrs = ['email', 'firstname', 'lastname', 'group_id']
    
    api_actions['create'] = _process_query(db_conn, _USERS_TO_CREATE_QUERY,
                                           ['email', 'firstname', 
                                            'lastname', 'group_id'])
    log.debug('Enabling users:')
    api_actions['enable'] = _process_query(db_conn, _USERS_TO_ENABLE_QUERY,
                                           ['avatar_id', 'email'])
    log.debug('Disabling users:')
    api_actions['disable'] = _process_query(db_conn, _USERS_TO_DISABLE_QUERY,
                                            ['avatar_id', 'email'])
    log.debug('Group change:')
    api_actions['group'] = _process_query(db_conn, _USERS_TO_PLANCHANGE_QUERY,
                                         ['avatar_id', 'email', 'group_id'])
    log.debug('Email change:')
    api_actions['email'] = _process_query(db_conn, _USERS_TO_EMAILCHANGE_QUERY,
                                          ['avatar_id', 'email', 'orig_email'])

    return api_actions


def run_group_management(config, db_conn):
    """
    Resolves differences between the LDAP and our idea of the SpiderOak user DB.
      
    :param config: configuration dict.  Should be the standard OpenManage setup.
    :param user_source: UserSource object to pull users from.
    :param db_conn: DB connection object
    """
    log = logging.getLogger('run_group_management')

    # First step, collect the users from the LDAP groups.
    ldap_conn = ldap_source.OMLDAPConnection(config["dir_uri"], config["dir_base_dn"], config["dir_user"], config["dir_password"])

    ldap_users = ldap_source.collect_groups(ldap_conn, config)
    change_groups = _calculate_changes_against_db(db_conn, config, ldap_users)

    runner = account_runner.AccountRunner(config, db_conn)
    runner.runall(change_groups)
    db_conn.commit()


def _run_disabled_users_for_repair(ldap_conn, config, desc, resultslist):
    """
    Creates a list of users who are disabled and still existing in the LDAP.
    """
    log = logging.getLogger("_run_disabled_users_for_repair")

    userlist = list()
    for result in resultslist:
        log.debug("Results for %s", result)
        user = {}
        for i in range(0,len(result)):
            user[desc[i][0]] = result[i]
            
        userlist.append(user)

    return list(ldap_source.get_user_guids(ldap_conn, config, userlist))
    

def run_db_repair(config, db_conn):
    """Repairs the current user DB and billing API versus LDAP."""
    # TODO: figure out what to do when email addresses *don't* match.
    log = logging.getLogger("run_db_repair")
    # Collect the users from LDAP, and insert into a temporary table.
    ldap_conn = ldap_source.OMLDAPConnection(config["dir_uri"],
                                             config["dir_base_dn"],
                                             config["dir_user"],
                                             config["dir_password"])

    log.info("Collecting LDAP groups")
    ldap_users = ldap_source.collect_groups(ldap_conn, config)
    cur = db_conn.cursor()
    cur.execute("CREATE TEMPORARY TABLE ldap_users (LIKE users) ON COMMIT DROP;")
    cur.execute("ALTER TABLE ldap_users DROP COLUMN avatar_id;")
    cur.execute("ALTER TABLE ldap_users DROP COLUMN enabled;")
    cur.executemany("INSERT INTO ldap_users (uniqueid, email, givenname, surname, group_id) VALUES (%(uniqueid)s, %(email)s, %(firstname)s, %(lastname)s, %(group_id)s);",
                    ldap_users)
    
    # Collect the users from the SpiderOak Accounts API, and insert into
    # a temporary table.
    log.info("Collecting SpiderOak user details")

    api = account_mgr.get_api(config)

    spider_users = api.list_users()
    
    for spider_user in spider_users:
        first_name, sep, last_name = spider_user['name'].strip().partition(' ')
        if not last_name: 
            last_name = ' '
        spider_user['firstname'] = first_name
        spider_user['lastname'] = last_name

    cur = db_conn.cursor()
    cur.execute("CREATE TEMPORARY TABLE spider_users (LIKE users) ON COMMIT DROP;")
    cur.execute("ALTER TABLE spider_users DROP COLUMN uniqueid;")
    cur.executemany("INSERT INTO spider_users "
                    "(avatar_id, email, givenname, surname, group_id, enabled) VALUES "
                    "(%(avatar_id)s, %(email)s, %(firstname)s, %(lastname)s, "
                    "%(group_id)s, %(enabled)s);",
                    spider_users)    

    # Delete duplicate rows
    cur.execute("DELETE FROM ldap_users "
                "WHERE ctid NOT IN "
                "(SELECT MAX(l.ctid) "
                "FROM ldap_users l "
                "GROUP BY l.email)"
               )

    # Clear out the current database.
    cur.execute("DELETE FROM users;")

    log.info("Inserting joined fields into the database")
    # Insert rows into users where email addresses match.
    cur.execute("INSERT INTO users "
                "SELECT l.uniqueid, s.email, s.avatar_id, s.givenname, "
                "s.surname, s.group_id, s.enabled "
                "FROM ldap_users l JOIN spider_users AS s ON l.email = s.email ")

    # Collect the list of users who are NOT in the LDAP
    # There are two types of users not in the LDAP sync groups we're looking through:
    #   1. Users who exist in the LDAP still, but not anymore in a monitored group
    #   2. Users who do not at all exist in the LDAP.
    #
    # Users in the first group we can enter back into the user sync database as disabled,
    # as we can locate some form of unique ID from the LDAP to put in the sync DB. The
    # second group needs to be just disabled on the Accounts API side. Note that users
    # in this second group will have to have the whole DB rebuilt if they reappear on the LDAP
    # and wish to continue using the same account.
    cur.execute("SELECT s.email, s.avatar_id, s.givenname, s.surname, s.group_id, s.enabled "
                "FROM spider_users s "
                "LEFT OUTER JOIN ldap_users l USING (email) "
                "WHERE l.email IS NULL")
    orphans = cur.fetchall()

    # "found_orphans" are the users who exist *somewhere* in the LDAP. lost_orphans do not.
    found_orphans = _run_disabled_users_for_repair(ldap_conn, config, cur.description, orphans)
    lost_orphans = set(orphans) - set(found_orphans)
    
    # Put the found orphans in the DB.
    cur.executemany("INSERT INTO users "
                    "(avatar_id, email, givenname, surname, group_id, enabled, uniqueid) "
                    "VALUES (%(avatar_id)s, %(email)s, %(givenname)s, %(surname)s, "
                    "        %(group_id)s, %(enabled)s, %(uniqueid)s);",
                    found_orphans)

    db_conn.commit()

    # ...and disable the lost orphans. We don't care about already disabled lost orphans,
    # we want to only disable orphans who are enabled so they can be rounded up and
    # deleted.
    
    
