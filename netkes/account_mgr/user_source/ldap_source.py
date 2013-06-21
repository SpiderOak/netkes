'''ldap_reader.py

Pulls the enterprise user groups from the LDAP server.

(c) 2011, SpiderOak, Inc. All rights reserved.

Function _PagedAsyncSearch() contains code as part of the
google-apps-for-your-domain-ldap-sync project
(https://code.google.com/p/google-apps-for-your-domain-ldap-sync/).
That code (c) 2006 Google, Inc.

For hacks to make this compatible with both python-ldap < 2.4 and >= 2.4,
please see our inspiration here:
http://planet.ergo-project.org/blog/jmeeuwen/2011/04/11/python-ldap-module-24-changes
'''

import ldap
import logging
import re
import uuid
from distutils import version

if version.StrictVersion('2.4.0') <= version.StrictVersion(ldap.__version__):
    LDAP_CONTROL_PAGED_RESULTS = ldap.CONTROL_PAGEDRESULTS
else:
    LDAP_CONTROL_PAGED_RESULTS = ldap.LDAP_CONTROL_PAGE_OID

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


class SimplePagedResultsControl(ldap.controls.SimplePagedResultsControl):
    """

        Python LDAP 2.4 and later breaks the API. This is an abstraction class
        so that we can handle either.
    """

    def __init__(self, page_size=0, cookie=''):
        if version.StrictVersion('2.4.0') <= version.StrictVersion(ldap.__version__):
            ldap.controls.SimplePagedResultsControl.__init__(
                    self,
                    size=page_size,
                    cookie=cookie
                )
        else:
            ldap.controls.SimplePagedResultsControl.__init__(
                    self,
                    LDAP_CONTROL_PAGED_RESULTS,
                    True,
                    (page_size, '')
                )

    def cookie(self):
        if version.StrictVersion('2.4.0') <= version.StrictVersion(ldap.__version__):
            return self.cookie
        else:
            return self.controlValue[1]

    def size(self):
        if version.StrictVersion('2.4.0') <= version.StrictVersion(ldap.__version__):
            return self.size
        else:
            return self.controlValue[0]


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


def _PagedAsyncSearch(ldap_conn, base_dn, scope, filterstr='(objectClass=*)', sizelimit=0, attrlist=None):
    """ Helper function that implements a paged LDAP search for
    the Search method below.
    Args:
    ldap_conn: our LDAP connection.
    base_dn: the base DN to start searching at.
    scope: LDAP scope to limit scope to.
    filterstr: LDAP filter to apply to the search
    sizelimit: max # of users to return.
    attrlist: list of attributes to return.  If null, all attributes
        are returned
    Returns:
      A list of users as returned by the LDAP search
    """

    paged_results_control = SimplePagedResultsControl(page_size=_PAGE_SIZE)
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
            if serverctrl.controlType == LDAP_CONTROL_PAGED_RESULTS:
                import pdb; pdb.set_trace()
                cookie = serverctrl.cookie()
                if cookie:
                    paged_results_control.controlValue = (_PAGE_SIZE, cookie)
                break
        if not cookie:
            break
    return users


def _get_group_ou(ldap_conn, config, group, dn):
    log = logging.getLogger('_get_group_ad %s' % (dn,))
    user_list = []
    for dn, result_dict in _PagedAsyncSearch(ldap_conn, ldap_conn.base_dn, ldap.SCOPE_SUBTREE,
                                             filterstr="(memberOf=%s)" % group['ldap_id'].encode('utf-8'),
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


def _get_group_group(ldap_conn, config, group):
    log = logging.getLogger('_get_group_group %s' % (group['ldap_id'],))
    user_list = []
    for dn, result_dict in _PagedAsyncSearch(ldap_conn, group['ldap_id'], ldap.SCOPE_BASE,
                                             sizelimit=200000,
                                             attrlist=[config['dir_member_source'],]):
        print dn, result_dict
        if dn is None:
            continue
        # Search LDAP to get User entries that match group
        for user in result_dict[config['dir_member_source']]:
            log.debug("Found user %s", user)
            
            if config['dir_type'] == 'posix':
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
                if config['dir_guid_source'] == 'objectGUID':
                    guid = str(
                        uuid.UUID(bytes_le=result_dict['objectGUID'][0])
                    )
                else:
                    guid = result_dict[config['dir_guid_source']][0]

                user_list.append({
                    'uniqueid'  : guid,
                    'email'     : user_dict[config['dir_username_source']][0],
                    'firstname' : user_dict[config['dir_fname_source']][0],
                    'lastname'  : user_dict[config['dir_lname_source']][0],
                    'group_id'  : group['group_id'],
                })

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

    print objClass

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

