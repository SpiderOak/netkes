'''
ldap_reader.py

Pulls the enterprise user groups from the LDAP server.

(c) 2011, SpiderOak, Inc.
'''

import ldap
import logging
import re

# MS ActiveDirectory does not properly give redirections; it passes
# redirects to the LDAP library, which dutifully follows them, but
# MSAD does not pass credentials along with the redirect process. This
# results in a case where we are using the same established, bound
# connection with our actual bound credentials having been
# stripped. The only recourse is to ignore referrals from LDAP
# servers.
ldap.set_option(ldap.OPT_REFERRALS, 0)

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


def _get_group_ad(ldap_conn, config, group, dn):
    log = logging.getLogger('_get_group_ad %s' % (dn,))
    user_list = []
    for dn, result_dict in ldap_conn.conn.search_s(
        ldap_conn.base_dn, ldap.SCOPE_SUBTREE, "(memberOf=%s)" % (dn,),
        [config['dir_guid_source'].encode('utf-8'),
         config['dir_username_source'].encode('utf-8'),
         config['dir_fname_source'].encode('utf-8'),
         config['dir_lname_source'].encode('utf-8')]
    ):
        if dn is None:
            continue
        log.debug("Appending user %s" % result_dict[config['dir_username_source']][0])
        user_list.append({
            'uniqueid'  : result_dict[config['dir_guid_source']][0],
            'email'     : result_dict[config['dir_username_source']][0],
            'firstname' : result_dict[config['dir_fname_source']][0],
            'lastname'  : result_dict[config['dir_lname_source']][0],
            'group_id'  : group['group_id'],
        })
    return user_list


def _get_group_posix(ldap_conn, config, group, dn):
    log = logging.getLogger('_get_group_posix %s' % (dn,))
    user_list = []
    for dn, result_dict in ldap_conn.conn.search_s(
        group['ldap_id'],
        ldap.SCOPE_SUBTREE,
        attrlist=[config['dir_guid_source'], config['dir_member_source']]
    ):
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

