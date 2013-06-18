"""
radius_source.py

Provides RADIUS authentication for the OpenManage stack.

This module *DOES NOT* provide user accounts management; that will have to be
provided via another plugin.

The following agent_config options are expected by this module:
rad_server: the RADIUS server we will be authenticating to
rad_secret: the RADIUS secret we will be using
rad_dict: the RADIUS dictionary to use.

(c) 2012 SpiderOak, Inc.
RADIUS auth code also contributed by RedHat, Inc.
"""

import logging
from socket import gethostname

import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary


def process_username(username, chop_at_symbol=True):
    """
    Selectively splits a username of the form "foo@bar.com" into just "foo" 
    for auth purposes.
    """
    
    if chop_at_symbol:
        username, _ = username.split('@', 1)

    return username

    
def can_auth(config, username, password):
    """
    Performs authentication against a RADIUS server.
    """

    log = logging.getLogger('radius_source.can_auth')

    log.debug("Attempting RADIUS auth to %s for user %s" % (config['rad_server'], username,))

    processed_user = process_username(username)

    # Create a RADIUS client to communicate with the server.
    srv = Client(
        server = config['rad_server'],
        secret = config['rad_secret'],
        dict   = Dictionary(config['rad_dictionary']),)

    req = srv.CreateAuthPacket(
        code = pyrad.packet.AccessRequest,
        User_Name = processed_user,
        NAS_Identifier = gethostname(),)

    req['User-Password'] = req.PwCrypt(password)

    try:
        reply = srv.SendPacket(req)
    except Exception:
        log.exception("Problem contacting RADIUS server")
        return False

    if reply.code == pyrad.packet.AccessAccept:
        log.info("User %s accepted by RADIUS" % (username,))
        return True

    log.info("User %s rejected by RADIUS" % (username,))
    return False
