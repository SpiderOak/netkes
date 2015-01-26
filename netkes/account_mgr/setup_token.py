'''
setup_token.py

(c) 2012 SpiderOak, Inc.

Manages setup authentication tokens.
'''

import base64
import datetime
import os
import sys

TOKEN_LENGTH = 30 # Tokens are 30-characters long. Note that we apply
                  # base64 encoding, so increasing this value may
                  # introduce padding characters.

def new_token():
    return base64.urlsafe_b64encode(os.urandom(TOKEN_LENGTH))

def create_token(db_conn, expiry=None, no_devices_only=True, single_use_only=True):
    """
    Creates an administrative setup token with the given options.

    :param db_conn: Open database connection.
    :param expiry: Datetime object of token's expiry, or None for now.
    :param no_devices_only: Restricts the token to use with accounts with no devices created.
    :param single_use_only: Restricts the token for single uses with a given user.

    :return: The 30-character string token.
    """

    token = new_token()

    create_token_query_base = "INSERT INTO admin_setup_tokens (token, no_devices_only, single_use_only"
    
    if expiry is None:
        create_token_query = create_token_query_base + ") VALUES (%s, %s, %s)"
        query_args = (token, no_devices_only, single_use_only, )
    else:
        create_token_query = create_token_query_base + ", expiry) VALUES (%s, %s, %s, %s)"
        query_args = (token, no_devices_only, single_use_only, expiry, )

    cur = db_conn.cursor()

    try:
        cur.execute(create_token_query, query_args)
    except Exception as e:
        db_conn.rollback()
        raise e
    else:
        db_conn.commit()

    return token

