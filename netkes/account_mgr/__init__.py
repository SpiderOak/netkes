'''
__init__.py

Init and common functions for the OpenManage user management system.

(c) 2011 SpiderOak, Inc.
'''

import os
import logging
import psycopg2
from accounts_api import Api
from contextlib import contextmanager

SELECT_ADMIN_TOKEN = '''
select no_devices_only, single_use_only,
    case when exists(select 1 from admin_token_avatar_use where token=%(token)s) then true
    else false end as token_used
from admin_setup_tokens
where token=%(token)s and expiry > now() and
    exists(select 1 from users where email=%(email)s and enabled)
'''

INSERT_ADMIN_AUTH_TOKEN_AVATAR_USE = '''
insert into admin_token_avatar_use (token, avatar_id)
values (%(token)s, (select avatar_id from users where email=%(email)s))
'''

@contextmanager
def get_cursor(config):
    try:
        conn = psycopg2.connect(database=config['db_db'],
                                user=config['db_user'],
                                password=config['db_pass'],
                                host=config['db_host'])
        yield conn.cursor()
    except:
        conn.rollback()
        raise
    else:
        conn.commit()

def get_api(config):
    return Api.create(config['api_root'],
                      config['api_user'], 
                      config['api_password'],)

def admin_token_auth(config, username, password):
    log = logging.getLogger("admin_token_auth")
    log.debug('checking admin auth code for username: %s' % username)
    api = get_api(config)
    user_token = dict(email=username, token=password)
    with get_cursor(config) as cur:
        cur.execute(SELECT_ADMIN_TOKEN, user_token)
        if cur.rowcount != 1:
            return False

        no_devices_only, single_use_only, token_used = cur.fetchone()

    if no_devices_only and api.list_devices(username):
        return False

    if single_use_only and token_used:
        return False

    with get_cursor(config) as cur:
        cur.execute(INSERT_ADMIN_AUTH_TOKEN_AVATAR_USE, user_token) 

    return True

def authenticator(config, username, password):
    """Authenticates users against OpenManage.

    This calls the correct authentication source to auth users.

    We expect a user_source module to offer a "can_auth" function taking three arguments:
    * The config dictionary
    * The username trying to authenticate
    * Their password

    The net_kes webserver should not at any time have to know or care how we
    are actually authenticating users, only that we do.
    """

    log = logging.getLogger("authenticator")

    auth_method = config.get('auth_method', None)
    auth_source = None

    print 'checking'
    if admin_token_auth(config, username, password):
        return True

    if auth_method == 'ldap':
        log.debug("Attempting to use LDAP simple bind for authenticating %s" % (username,))
        from account_mgr.user_source import ldap_source
        auth_source = ldap_source

    elif auth_method == 'radius':
        log.debug("Attempting to use RADIUS authentication for %s" % (username,))
        from account_mgr.user_source import radius_source
        auth_source = radius_source

    elif auth_method == 'local':
        log.debug("Attempting to use local authentication for %s" % (username,))
        from account_mgr.user_source import local_source
        auth_source = local_source

    else:
        log.error("No user authentication source provided, please check agent_config.")
        log.warn("Returning failed authentication for %s" % (username,))
        return False

    return auth_source.can_auth(config, username, password)
