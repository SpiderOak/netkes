'''ldap_reader.py

Pulls the enterprise user groups from the LDAP server.

(c) 2011, SpiderOak, Inc. All rights reserved.

Function _PagedAsyncSearch() contains code as part of the
google-apps-for-your-domain-ldap-sync project
(https://code.google.com/p/google-apps-for-your-domain-ldap-sync/).
That code (c) 2006 Google, Inc.
'''

import ldap
import logging
import re
import uuid

try:
    from ldap.controls import SimplePagedResultsControl
except ImportError:
    print "Client LDAP does not support paged results"

# MS ActiveDirectory does not properly give redirections; it passes
# redirects to the LDAP library, which dutifully follows them, but
# MSAD does not pass credentials along with the redirect process. This
# results in a case where we are using the same established, bound
# connection with our actual bound credentials having been
# stripped. The only recourse is to ignore referrals from LDAP
# servers.
ldap.set_option(ldap.OPT_REFERRALS, 0)

# Maximum number of results we're going to try to get on a single query.
_PAGE_SIZE = 900

# Are we going to use paged queries?
_TRY_PAGED_QUERIES = True

class InvalidGroupConfiguration(Exception):
    '''
    Thrown when invalid group configuration is used.
    '''
    pass

class OMLDAPConnection(object):
    def __init__(self, uri, base_dn, username, password):
        log = logging.getLogger('OMLDAPConnection __init__')
        self.conn = ldap.initialize(uri)
        self.conn.simple_bind_s(username, password)
        log.debug("Bound to %s as %s" % (uri, username,))
        self.conn.protocol_version = 3

        self.base_dn = base_dn


def get_auth_username(config, username):
    """
    Returns the appropriate username to authenticate against.

    Will return either the `username` argument or a username gotten from the LDAP. 
    """
    # If we have no configuration telling us to lookup a different username, 
    # just return here.
    log = logging.getLogger("get_auth_username")

    if config.get('dir_auth_username', None) is None:
        return username

    my_ldap = OMLDAPConnection(config['dir_uri'], config['dir_base_dn'],
                               config['dir_user'], config['dir_password'])
    results = my_ldap.conn.search_s(my_ldap.base_dn,
                                    filterstr = '(%s=%s)' % \
                                         (config['dir_username_source'], username,),
                                    scope = ldap.SCOPE_SUBTREE,
                                    attrlist = [config['dir_auth_username'],])

    if len(results) < 1:
        raise Exception("No LDAP user found for username %s" % (username,))

    # Filter out all returned entries where the DN doesn't exist.
    result_list = [result for dn, result in results if dn is not None]

    # Having dupes is not good.
    if len(result_list) > 1:
        raise Exception("Too many LDAP users found via field %s for username %s" % 
                        (config['dir_username_source'], username,))

    return result_list[0][config['dir_auth_username']][0]


def can_auth(config, username, password):
    '''
    Checks the ability of the given username and password to connect to the AD.
    Returns true if valid, false if not.
    '''
    log = logging.getLogger("can_bind")
    # Throw out empty passwords.
    if password == "":
        return False

    conn = ldap.initialize(config['dir_uri'])
    try:
        auth_user = get_auth_username(config, username)
        conn.simple_bind_s(auth_user, password)
    # ANY failure here results in a failure to auth.  No exceptions!
    except Exception:
        log.exception("Failed on LDAP bind")
        return False

    return True


def collect_groups(conn, config):
    '''
    Returns a list of lists of users per user group.
    The user groups are a list of LDAP DNs.
    '''

    result_groups = []

    for group in config['groups']:
        result_groups.extend(get_group(conn, config, group))

    return result_groups



def _PagedAsyncSearch(ldap_conn, sizelimit, base_dn, scope, filterstr='(objectClass=*)', attrlist=None):
    """ Helper function that implements a paged LDAP search for
    the Search method below.
    Args:
    ldap_conn: our OMLdapConnection object
    sizelimit: max # of users to return.
    filterstr: LDAP filter to apply to the search
    attrlist: list of attributes to return.  If null, all attributes
        are returned
    Returns:
      A list of users as returned by the LDAP search
    """

    paged_results_control = SimplePagedResultsControl(
        ldap.LDAP_CONTROL_PAGE_OID, True, (_PAGE_SIZE, ''))
    logging.debug('Paged search on %s for %s', base_dn, filterstr)
    users = []
    ix = 0
    while True: 
        if _PAGE_SIZE == 0:
            serverctrls = []
        else:
            serverctrls = [paged_results_control]
        msgid = ldap_conn.conn.search_ext(base_dn, scope, 
                                     filterstr, attrlist=attrlist, serverctrls=serverctrls)
        res = ldap_conn.conn.result3(msgid=msgid)
        unused_code, results, unused_msgid, serverctrls = res
        for result in results:
            ix += 1
            users.append(result)
            if sizelimit and ix >= sizelimit:
                break
        if sizelimit and ix >= sizelimit:
            break
        cookie = None 
        for serverctrl in serverctrls:
            if serverctrl.controlType == ldap.LDAP_CONTROL_PAGE_OID:
                unused_est, cookie = serverctrl.controlValue
                if cookie:
                    paged_results_control.controlValue = (_PAGE_SIZE, cookie)
                break
        if not cookie:
            break
    return users


def _create_attrlist(config):
    """
    Creates an LDAP search attribute list based on our configuration.
    """

    attrlist = [config['dir_guid_source'].encode('utf-8'),
                config['dir_username_source'].encode('utf-8'),
                config['dir_fname_source'].encode('utf-8'),
                config['dir_lname_source'].encode('utf-8'),
                ]

    if 'dir_email_source' in config:
        attrlist.append(config['dir_email_source'].encode('utf-8'))

    return attrlist


def _fix_guid(config, guid):
    """
    Ensures GUIDs are properly encoded if they're from MSAD
    """
    if config['dir_guid_source'] == 'objectGUID':
        return str(
            uuid.UUID(bytes_le=guid)
        )
    else:
        return guid


def get_user_guids(ldap_conn, config, userlist):
    """Returns a generator of users combined with their UDIDs from the LDAP.

    Required to properly enumerate users who exist in the SpiderOak
    user directory and not in the customer LDAP.
    """
    log = logging.getLogger('get_disabled_users')

    if 'dir_email_source' in config:
        email_attribute_field = 'dir_email_source'
    else:
        email_attribute_field = 'dir_username_source'

    for user in userlist:
        filterstr = "(%s=%s)" % (config[email_attribute_field], user['email'],)
        user_result_list = ldap_conn.conn.search_s(
            base=ldap_conn.base_dn,
            scope=ldap.SCOPE_SUBTREE,
            filterstr=filterstr,
            attrlist=[config['dir_guid_source'],])

        user_results = [(dn, results,) for dn, results in user_result_list if dn is not None]
        if len(user_results) != 1:
            log.warn("No LDAP results found for %s, USER IS ORPHANED", user['email'])
            continue

        # make sure we don't muck with the array variables by making a copy.
        newuser = dict(user)

        # Note to self: whoever thought wrapping everything in arrays
        # of tuples of dictionaries of arrays DESERVES SCORN.
        newuser['uniqueid'] = _fix_guid(config, user_results[0][1][config['dir_guid_source']][0])
        yield newuser


def _build_user_dict(config, result_dict, group_id):
    """
    Creates a dictionary to append to the user results list, with arrangement based on
    configuration.
    """

    user = {
        'uniqueid'  : _fix_guid(config,
                                result_dict[config['dir_guid_source']][0]),
        'firstname' : result_dict[config['dir_fname_source']][0],
        'lastname'  : result_dict[config['dir_lname_source']][0],
        'group_id'  : group_id,
    }

    if 'dir_email_source' in config:
        user['email'] = result_dict[config['dir_email_source']][0]
        user['username'] = result_dict[config['dir_username_source']][0]
    else:
        user['email'] = result_dict[config['dir_username_source']][0]

    return user



def _get_group_ou(ldap_conn, config, group):
    log = logging.getLogger('_get_group_ou %s' % (group['ldap_id'],))
    user_list = []
    for dn, result_dict in _PagedAsyncSearch(ldap_conn, 
                                             sizelimit=200000,
                                             base_dn = group['ldap_id'],
                                             scope=ldap.SCOPE_SUBTREE,
                                             filterstr = "(|(objectClass=person)(objectClass=user)(objectClass=organizationalUser))",
                                             attrlist=_create_attrlist(config)):

        if dn is None:
            continue
        if config['dir_username_source'] not in result_dict:
            log.info("User %s lacks %s, skipping", dn, config['dir_username_source'])
            continue

        log.debug("Appending user %s", result_dict[config['dir_username_source']][0])

        user = _build_user_dict(config, result_dict, group['group_id'])
        user_list.append(user)


    return user_list


def _build_user_details(ldap_conn, config, group, uid):
    log = logging.getLogger('_build_user_details')
    user = ldap_conn.conn.search_s(
            uid,
            ldap.SCOPE_BASE,
            attrlist = _create_attrlist(config))

    dn, user_dict = user[0]

    if dn is None:
        return None
    log.debug("Appending user %s", user)

    return _build_user_dict(user_dict, config, group['group_id'])


def _get_group_group(ldap_conn, config, group):
    log = logging.getLogger('_get_group_group %s' % (group['ldap_id'],))
    user_list = []
    for dn, result_dict in _PagedAsyncSearch(ldap_conn,
                                             sizelimit=200000,
                                             base_dn=group['ldap_id'],
                                             scope=ldap.SCOPE_BASE,
                                             attrlist=[config['dir_member_source']]):

        if dn is None:
            continue
        # Search LDAP to get User entries that match group
        for user in result_dict[config['dir_member_source']]:
            log.debug("Found user %s", user)
            
            user_details = _build_user_details(ldap_conn, config, group, user)

            # Add each user that matches
            if user_details is not None:
                user_list.append(user_details)

    return user_list


_GROUP_GETTERS = {
    'group': _get_group_group,
    'ou': _get_group_ou,
}

def _determine_group_type(ldap_conn, group):
    '''
    Determines if the group we're dealing with is either an OU or an LDAP group.
    '''

    objClass = ldap_conn.conn.search_s(
        group['ldap_id'],
        ldap.SCOPE_BASE,
        attrlist=['objectClass'])

    # The following are objectTypes for OUs.
    if 'container' in objClass[0][1]['objectClass'] or \
       'organizationalUnit' in objClass[0][1]['objectClass']:
        return 'ou'
    else:
        return 'group'

            
def get_group(ldap_conn, config, group):
    '''
    Returns a list of user dicts for the specified group.

    user dict keys: uniqueid, email, firstname, lastname, group_id
    '''
    # TODO: figure out how to smoothly handle using GUIDs in configuration.
    #       AD stores GUIDs as a very unfriendly 16-byte value.
    log = logging.getLogger("get_group %d" % (group['group_id'],))

    group_getter = _GROUP_GETTERS[_determine_group_type(ldap_conn, group)]
    
    log.debug("Group DN: %s", group['ldap_id'])
    user_list = group_getter(ldap_conn, config, group)
    log.info("Found %d users", len(user_list))

    return user_list

