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

_ATTR_KEY_RANGE_REGEXP = re.compile(r"^([^;]+);range=(\d+)-(\d+|\*)$")

class InvalidGroupConfiguration(Exception):
    '''
    Thrown when invalid group configuration is used.
    '''
    pass

class TooManyLdapResults(Exception):
    '''
    Thrown when we get too many LDAP results.
    '''
    pass

class NotEnoughLdapResults(Exception):
    '''
    Thrown when we don't get enough LDAP results.
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

class LdapGroup(object):
    """
    Virtual class defining an arbitrary directory-fed group
    (there are so far concrete implementations for LDAP 'Security Groups' and
    'Organizational Units'
    """

    _ou_object_classes = set(['container', 'organizationalUnit'])

    def __init__(self, ldap_conn, config, ldap_id, group_id):
        log = logging.getLogger('LdapGroup __init__')
        self.ldap_conn = ldap_conn
        self.ldap_id = ldap_id
        self.group_id = group_id
        self.config = config
        
        # Locally cached list of users.
        self._users = None

    @classmethod
    def get_group(cls, ldap_conn, config, ldap_id, group_id):
        '''
        Creates an appropriate subclass instance based on the type of group.
        '''
        group_type = LdapGroup._determine_group_type(ldap_conn, ldap_id)
        if group_type == 'ou':
            return LdapOuGroup(ldap_conn, config, ldap_id, group_id)
        elif group_type == 'group':
            return LdapGroupGroup(ldap_conn, config, ldap_id, group_id)
        else:
            raise RuntimeError("unrecognized group_type for group_id %r: %r" 
                % (ldap_id, group_type, ))

    @classmethod
    def _determine_group_type(cls, ldap_conn, ldap_id):
        '''
        Determines if the group we're dealing with is either an OU or an LDAP group.
        '''

        results = ldap_conn.conn.search_s(
            ldap_id,
            ldap.SCOPE_BASE,
            attrlist=['objectClass'])
        
        # The following are objectTypes for OUs.
        # Possibly multiple entries come back for objectClass:
        for objClass in results[0][1]['objectClass']:
            if objClass in cls._ou_object_classes:
                return 'ou'

        else:
            return 'group'

    def _create_attrlist(self):
        """
        Creates an LDAP search attribute list based on our configuration.
        """

        attrlist = [self.config['dir_guid_source'].encode('utf-8'),
                    self.config['dir_username_source'].encode('utf-8'),
                    self.config['dir_fname_source'].encode('utf-8'),
                    self.config['dir_lname_source'].encode('utf-8'),
                    ]

        if self.config.get('dir_email_source', None) not in (None, '',):
            attrlist.append(self.config['dir_email_source'].encode('utf-8'))

        return attrlist


    def _build_user_dict(self, result_dict):
        """
        Creates a dictionary to append to the user results list, with arrangement based on
        configuration.
        """

        user = {
            'uniqueid'  : _fix_guid(self.config,
                                    result_dict[self.config['dir_guid_source']][0]),
            'firstname' : result_dict.get(self.config['dir_fname_source'], [' '])[0],
            'lastname'  : result_dict.get(self.config['dir_lname_source'], [' '])[0],
            'group_id'  : self.group_id,
        }

        if self.config.get('dir_email_source', None) not in (None, '',):
            user['email'] = result_dict[self.config['dir_email_source']][0]
            user['username'] = result_dict[self.config['dir_username_source']][0]
        else:
            user['email'] = result_dict[self.config['dir_username_source']][0]

        return user


    def _user_for_uid(self, uid, uid_field):
        log = logging.getLogger("_user_for_uid")
        results = self.ldap_conn.conn.search_s(
            base      = self.config['dir_base_dn'],
            scope     = ldap.SCOPE_SUBTREE,
            filterstr = "(%s=%s)" % (uid_field, uid,),
            attrlist  = self._create_attrlist())

        try:
            dn, result = _filter_ldap_results(results)
        except NotEnoughLdapResults:
            log.warn("No results for uid %s" % (uid,))
            return None
        except TooManyLdapResults:
            log.warn("Multiple results for uid %s" % (uid,))
            return None

        return result

    def _user_for_dn(self, uid):
        user = self.ldap_conn.conn.search_s(
                uid,
                ldap.SCOPE_BASE,
                attrlist = self._create_attrlist())

        dn, user_dict = user[0]

        if dn is None:
            return None
        
        return user_dict


    def _build_user_details(self, uid, uid_field):
        '''Gathers details from the user from LDAP, and creates a user dictionary
        out of that.

        LDAP search is abstracted out based on the uid_field passed
        in. A value of None means we have a proper DN to search
        against, otherwise it represents a username field we need to
        search for.

        '''
        log = logging.getLogger('_build_user_details')
        if uid_field not in (None, ''):
            user_dict = self._user_for_uid(uid, uid_field)
        else:
            user_dict = self._user_for_dn(uid)

        if user_dict is None:
            return None

        log.debug("Appending user %s", user_dict)

        return self._build_user_dict(user_dict)


    def __iter__(self):
        """
        Provides a iterable over the (cached on first use) user list.
        """
        if self._users is None:
            # userlist() is a virtual method for this base class, so we
            # disable pylint complaints on userlist not existing.
            self._users = self.userlist() #pylint: disable=E1101

        for user in self._users:
            yield user

class LdapOuGroup(LdapGroup):
    """
    Concrete implemenation of LdapGroup for LDAP OU's
    (i.e. does the userlist in the way needed by OU's)
    """
    def __init__(self, ldap_conn, config, ldap_id, group_id):
        super(LdapOuGroup, self).__init__(ldap_conn, config, ldap_id, group_id)

    def userlist(self):
        log = logging.getLogger('_get_group_ou %s' % (self.ldap_id,))
        user_list = []
        for dn, result_dict in _PagedAsyncSearch(self.ldap_conn, 
                                                 sizelimit=200000,
                                                 base_dn = self.ldap_id,
                                                 scope=ldap.SCOPE_SUBTREE,
                                                 filterstr = "(|(objectClass=person)(objectClass=user)(objectClass=organizationalUser))",
                                                 attrlist=self._create_attrlist()):

            if dn is None or not result_dict:
                continue
            if self.config['dir_username_source'] not in result_dict:
                log.info("User %s lacks %s, skipping", dn, self.config['dir_username_source'])
                continue

            log.debug("Appending user %s", result_dict[self.config['dir_username_source']][0])

            user = self._build_user_dict(result_dict)
            user_list.append(user)

        return user_list
    

class LdapGroupGroup(LdapGroup):
    def __init__(self, ldap_conn, config, ldap_id, group_id):
        super(LdapGroupGroup, self).__init__(ldap_conn, config, ldap_id, group_id)

    def _check_result_keys_for_range(self, keys):
        # Check for a ranged result key. Scan the list of result keys
        # and match against a regex.
        result_key = self.config['dir_member_source']
        end_range = None
        for key in keys:
            match = _ATTR_KEY_RANGE_REGEXP.match(key)
            if match is not None:
                result_key = key
                if match.group(3) != '*':
                    end_range = int(match.group(3))
                else:
                    end_range = None
                break
        
        return (result_key, end_range,)


    def _pas_ranged_results_wrapper(self, startrange = None):
        '''
        Wraps PagedAsyncSearch for ranged results from our friends, Microsoft.

        See https://github.com/SpiderOak/netkes/issues/32.

        NOTE! This function is recursive!
        '''
        log = logging.getLogger('_pas_ranged_results_wrapper')
        if startrange is None:
            attrstring = self.config['dir_member_source']
        else:
            attrstring = "%s;range=%d-*" % \
                         (self.config['dir_member_source'], startrange,)

        # We expect one and only one result here.
        results = _PagedAsyncSearch(self.ldap_conn,
                                    sizelimit=200000,
                                    base_dn=self.ldap_id,
                                    scope=ldap.SCOPE_BASE,
                                    attrlist=[attrstring])

        try:
            dn, result = _filter_ldap_results(results)
        except TooManyLdapResults:
            raise Exception("Multiple results for a single unique DN?")
        except NotEnoughLdapResults:
            # group doesn't exits (and we should have blown up earlier)
            # so we should never get here.
            log.error("NotEnoughLdapResults: "
                      "this should not happen: ldap_id %r"
                      % (self.ldap_id, ))
            return []

        result_dict = result
        if not result_dict:
            return []

        result_key, end_range = self._check_result_keys_for_range(result_dict.keys())
        users = result_dict[result_key]
        if end_range is None:
            return users
           
        users.extend(self._pas_ranged_results_wrapper(end_range + 1))
        return users


    def userlist(self):
        log = logging.getLogger('_get_group_group %s' % (self.ldap_id,))
        user_list = []
        for user in self._pas_ranged_results_wrapper():
            log.debug("Found user %s", user)

            user_details = self._build_user_details(user,
                                                    self.config.get('dir_uid_source', None))

            if user_details is None:
                continue

            # Add each user that matches
            if not user_details['firstname'] and not user_details['lastname']:
                msg = 'Unable to process user %s. The user had no first name or last name.' % user_details
                print msg
                log.error(msg)
            elif user_details is not None:
                user_list.append(user_details)

        return user_list

def _filter_ldap_results(results):
    '''
    Checks LDAP results for too many or too little results.
    '''

    # Make sure there's something there to begin with.
    if len(results) < 1:
        raise NotEnoughLdapResults()

    result_list = [(dn, result) for dn, result in results if dn is not None ]

    # Having more than one result for this is not good.
    if len(result_list) > 1:
        raise TooManyLdapResults()

    return result_list[0]
    
def get_auth_username(config, username):
    """
    Returns the appropriate username to authenticate against.

    Will return either the `username` argument or a username gotten from the LDAP. 
    """
    # If we have no configuration telling us to lookup a different username, 
    # just return here.
    log = logging.getLogger("get_auth_username")

    if (config.get('dir_auth_username') in (None, '',) and 
        config.get('dir_auth_source') in (None, '',)):
        return username

    my_ldap = OMLDAPConnection(config['dir_uri'], config['dir_base_dn'],
                               config['dir_user'], config['dir_password'])

    if config.get('dir_auth_source') == 'dn':
        results = my_ldap.conn.search_s(my_ldap.base_dn,
                                        filterstr = '(%s=%s)' % \
                                            (config['dir_username_source'], username,),
                                        scope = ldap.SCOPE_SUBTREE,)
    else:
        results = my_ldap.conn.search_s(my_ldap.base_dn,
                                        filterstr = '(%s=%s)' % \
                                            (config['dir_username_source'], username,),
                                        scope = ldap.SCOPE_SUBTREE,
                                        attrlist = [config['dir_auth_username'],])

    try:
        dn, result = _filter_ldap_results(results)
    except NotEnoughLdapResults:
        raise Exception("No LDAP user found for username %s" % (username,))
    except TooManyLdapResults:
        raise Exception("Too many LDAP users found via field %s for username %s" % 
                        (config['dir_username_source'], username,))

    if config.get('dir_auth_source') == 'dn':
        return dn
    else:
        return result[config['dir_auth_username']][0]



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
    Returns a flat list users found in all the groups listed in our config.
    Each element in the list is a dictionary (email, username, group_id, etc)
    '''
    log = logging.getLogger("collect_groups")

    result_users = []

    for group in config['groups']:
        # Make sure we don't try to sync non-LDAP groups.
        if group['user_source'] is not 'ldap':
            continue
        ldap_group = LdapGroup.get_group(conn, config,
                                         group['ldap_id'],
                                         group['group_id'])
        # the group object is iterable, and iterates the users in the group
        #log.debug("%d users in group %r" % ( len(ldap_group), 

        result_users.extend(ldap_group)

    return result_users


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

