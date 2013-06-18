'''
local_source.py

Provides self-contained user management functionality on the virtual appliance.

(c) 2012, SpiderOak, Inc.
'''

import logging
import psycopg2

log = logging.getLogger('local_source')
try:
    import bcrypt
except ImportError:
    log.warn('no bcrypt; ldap only this system')

from common import get_config

# This is only filled in the event of hitting authenticator and needing to connect to a DB.
_AUTHENTICATOR_DB_CONN = None

_PW_HASH_SELECT='''
SELECT email, pw_hash
FROM passwords WHERE email=%s;'''
def check_local_auth(db_conn, username, password):
    log = logging.getLogger("check_local_auth")
    log.info('login: %s %s' % (username, password,))
    cur = db_conn.cursor()
    cur.execute(_PW_HASH_SELECT, (username,))
    if cur.rowcount != 1:
        return False

    row = cur.fetchone()

    try:
        return bcrypt.hashpw(password, row[1]) == row[1]
    except ValueError:
        return False

def _get_db_conn(config):
    global _AUTHENTICATOR_DB_CONN
    if _AUTHENTICATOR_DB_CONN is None:
        _AUTHENTICATOR_DB_CONN = psycopg2.connect(database=config['db_db'],
                                                  user=config['db_user'],
                                                  password=config['db_pass'],
                                                  host=config['db_host'])

    return _AUTHENTICATOR_DB_CONN

def can_auth(config, username, password):
    return check_local_auth(_get_db_conn(config), username, password)

def set_user_password(db_conn, email, password):
    """
    Sets the password for the user.

    This is secretly a wrapper for :func:`set_multi_passwords`.

    :param db_conn: DB connection object
    :param email: User's email
    :param password: User's password.

    """
    log = logging.getLogger("set_user_password")
    set_multi_passwords(db_conn, [email], [password])

def set_multi_passwords(db_conn, emails, passwords):
    """
    Sets passwords for the given emails.

    :param emails: List of email addresses.
    :param passwords: List of passwords to set for the given emails.
    :raises: TypeError

    """
    if len(emails) != len(passwords):
        raise TypeError("Argument lengths do not match!")
    hashed_pws = (bcrypt.hashpw(pw, bcrypt.gensalt()) for pw in passwords)
    cur = db_conn.cursor()

    cur.executemany(
        "SELECT upsert_password(%s, %s)", itertools.izip(emails, hashed_pws)
    )

    db_conn.commit()
