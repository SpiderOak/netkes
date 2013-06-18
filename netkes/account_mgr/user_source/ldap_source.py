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
        conn.simple_bind_s(username, password)
    # ANY failure here results in a failure to auth.  No exceptions!
    except Exception:
        log.exception("Failed on LDAP bind")
        return False

    return True


def ldap_connect(uri, base_dn, username, password):
    ''' 
    Returns a tuple of (bound LDAP connection object, base DN).
    Accepts a directory containing our connection settings.
    '''
    log = logging.getLogger('ldap_connect')
    conn = ldap.initialize(uri)
    conn.simple_bind_s(username, password)
    log.debug("Bound to %s as %s" % (uri, username,))
    return (conn, base_dn, )

def collect_groups(conn, config):
    '''
    Returns a list of lists of users per user group.
    The user groups are a list of LDAP DNs.
    '''

    result_groups = []

    for group in config['groups']:
        result_groups.extend(get_group(conn, config, group))

    return result_groups


def group_by_guid(conn, guid):
    '''
    Returns the DN of a group given the GUID.
    Active Directory-only.
    '''
    results = conn.conn.search_s(conn.base_dn,
                               ldap.SCOPE_SUBTREE,
                               "(objectGUID=%s)" % (guid,),
                               ["dn"],
                               )
    return results


def _PagedAsyncSearch(ldap_conn, query, sizelimit, attrlist=None):
    """ Helper function that implements a paged LDAP search for
    the Search method below.
    Args:
    query: LDAP filter to apply to the search
    sizelimit: max # of users to return.
    attrlist: list of attributes to return.  If null, all attributes
        are returned
    Returns:
      A list of users as returned by the LDAP search
    """

    paged_results_control = SimplePagedResultsControl(
        ldap.LDAP_CONTROL_PAGE_OID, True, (_PAGE_SIZE, ''))
    logging.debug('Paged search on %s for %s', ldap_conn.base_dn, query)
    users = []
    ix = 0
    while True: 
        if _PAGE_SIZE == 0:
            serverctrls = []
        else:
            serverctrls = [paged_results_control]
        msgid = ldap_conn.conn.search_ext(ldap_conn.base_dn, ldap.SCOPE_SUBTREE, 
                                     query, attrlist=attrlist, serverctrls=serverctrls)
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


def _get_group_ad(ldap_conn, config, group, dn):
    log = logging.getLogger('_get_group_ad %s' % (dn,))
    user_list = []
    for dn, result_dict in _PagedAsyncSearch(ldap_conn,
                                             query="(memberOf=%s)" % group['ldap_id'].encode('utf-8'),
                                             sizelimit=200000,
                                             attrlist=[config['dir_guid_source'].encode('utf-8'),
                                                       config['dir_username_source'].encode('utf-8'),
                                                       config['dir_fname_source'].encode('utf-8'),
                                                       config['dir_lname_source'].encode('utf-8')]):
        if dn is None:
            continue
        log.debug("Appending user %s", result_dict[config['dir_username_source']][0])

        # Detect if we're using objectGUIDs, and use the uuid module to auto-translate
        # into a string.
        if config['dir_guid_source'] == 'objectGUID':
            guid = str(
                uuid.UUID(bytes_le=result_dict['objectGUID'][0])
            )
        else:
            guid = result_dict[config['dir_guid_source']][0]

        user_list.append({
            'uniqueid'  : guid,
            'email'     : result_dict[config['dir_username_source']][0],
            'firstname' : result_dict[config['dir_fname_source']][0],
            'lastname'  : result_dict[config['dir_lname_source']][0],
            'group_id'  : group['group_id'],
        })
    return user_list


def _get_group_posix(ldap_conn, config, group, dn):
    log = logging.getLogger('_get_group_posix %s' % (dn,))
    user_list = []
    for dn, result_dict in _PagedAsyncSearch(ldap_conn,
                                             query=group['ldap_id'],
                                             sizelimit=200000,
                                             attrlist=[config['dir_guid_source'],
                                                       config['dir_member_source']]):
        print dn, result_dict
        if dn is None:
            continue
        # Search LDAP to get User entries that match group
        for user in result_dict[config['dir_member_source']]:
            log.debug("Found user %s", user)
            
            # Split apart the uid from the rest of the member_source 
            regex_result = re.search(r'^(uid=\w+),', user)
            uid = regex_result.group(1)

            # Add each user that matches
            for dn, user_dict in ldap_conn.conn.search_s(
                ldap_conn.base_dn,
                ldap.SCOPE_SUBTREE, uid,
                [config['dir_guid_source'],
                 config['dir_fname_source'],
                 config['dir_lname_source'],
                 config['dir_username_source']]
            ):
                if dn is None:
                    continue
                log.debug("Appending user %s", user)
                user_list.append({
                    'uniqueid'  : user_dict[config['dir_guid_source']][0],
                    'email'     : user_dict[config['dir_username_source']][0],
                    'firstname' : user_dict[config['dir_fname_source']][0],
                    'lastname'  : user_dict[config['dir_lname_source']][0],
                    'group_id'  : group['group_id'],
                })

    return user_list

_GROUP_GETTERS = {
    'ad': _get_group_ad,
    'posix': _get_group_posix,
}


def get_group(ldap_conn, config, group):
    '''
    Returns a list of user dicts for the specified group.

    user dict keys: uniqueid, email, firstname, lastname, group_id
    '''
    # TODO: figure out how to smoothly handle using GUIDs in configuration.
    #       AD stores GUIDs as a very unfriendly 16-byte value.
    log = logging.getLogger("get_group %d" % (group['group_id'],))
    if group['type'].lower() != "dn":
        raise InvalidGroupConfiguration("passed a group value != 'dn'")
    dn = group['ldap_id']

    try:
        group_getter = _GROUP_GETTERS[config.get('dir_type', 'ad').lower()]
    except KeyError:
        raise InvalidGroupConfiguration(
            "unknown dir_type %r" % (config['dir_type'],))

    log.debug("Group DN: %s", dn)
    user_list = group_getter(ldap_conn, config, group, dn)
    log.info("Found %d users", len(user_list))

    return user_list

