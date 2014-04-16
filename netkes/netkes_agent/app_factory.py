import logging
import os
import re
import nacl.secret
import bcrypt
import json
from binascii import b2a_base64
import time

from urllib import unquote
from wsgi_util.router import router
from wsgi_util.http import BadRequest, SuperSimple, NotFound, Forbidden, ServerError
from wsgi_util.post_util import read_postdata, read_querydata

from common import get_config, read_config_file, set_config, validate_config, NetKesConfigError
from account_mgr import authenticator
from key_escrow import server
from Pandora import serial

SESSION = {}
CHALLENGE_EXPIRATION_TIME = 60
KEYLEN = nacl.secret.SecretBox.KEY_SIZE
ITERATIONS = 100    # from py-bcrypt readme, maybe need to tweak this

def setup_logging():
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-7s %(name)-15s: %(message)s')
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)

    if 'SPIDEROAK_NETKES_LOG_DEBUG' in os.environ:
        logging.root.setLevel(logging.DEBUG)
        logging.info("Debug logging enabled. Warning, lots of output!")
    else:
        logging.root.setLevel(logging.INFO)

def setup_application():
    config = get_config()
    if config is not None:
        return
    config = read_config_file()
    validate_config(config)
    set_config(config)


setup_logging()
setup_application()
serial.register_all()

@read_querydata
def start_auth_session(environ, start_response):
    log = logging.getLogger("get_layers")

    log.debug("start")
    try:
        brand_identifier = environ['query_data']['brand_id'][0]
        username = environ['query_data']['username'][0]
    except KeyError:
        log.error("Got bad request.")
        return BadRequest()(environ, start_response)

    challenge = b2a_base64(os.urandom(32))
    SESSION[unquote(username)] = (challenge, time.time())

    try:
        layer_data = server.get_escrow_layers(brand_identifier)
    except (KeyError, IOError,):
        log.warn("Got missing brand_identifier: %s" % (brand_identifier,))
        return NotFound()(environ, start_response)

    log.info("Returning escrow keys for %s" % (brand_identifier,))

    data = dict(layer_data=b2a_base64(layer_data),
                challenge=challenge)

    return SuperSimple(json.dumps(data))(environ, start_response)

def valid_challenge(username, challenge):
    if username not in SESSION:
        return False
    session_challenge = SESSION[username]
    if session_challenge[1] + CHALLENGE_EXPIRATION_TIME < time.time(): 
        return False

    return session_challenge[0] == challenge #TODO make this compare constant time

def login_required(fun):
    def decorator(environ, start_response):
        log = logging.getLogger('login_required')
        log.debug("start")
        try:
            brand_identifier = environ['query_data']['brand_id'][0]
            username = environ['query_data']['username'][0]
            auth = environ['query_data']['auth'][0]
            serial_sign_key = environ['post_data']['sign_key'][0]
            layer_count = int(environ['post_data'].get('layer_count', [])[0])
        except KeyError:
            log.error("Got bad request.")
            return BadRequest()(environ, start_response)

        sign_key = serial.loads(serial_sign_key)
        decoded_user = unquote(username)

        try:
            data =  server.read_escrow_data(
                brand_identifier, 
                auth, 
                sign_key=sign_key, 
                layer_count=layer_count,
            )

            plaintext_auth = json.loads(data)
        except KeyError:
            log.warn("missing identifier %s" % (brand_identifier,))
            return NotFound()(environ, start_response)
        except ValueError:
            log.warn("bad values for authenticating user %s" % (decoded_user,))
            return BadRequest()(environ, start_response)
        except Exception:
            log.exception("server.read_escrow_data failed for user %s brand %s"
                    % (decoded_user, brand_identifier,))
            return ServerError()(environ, start_response)

        challenge = valid_challenge(username, plaintext_auth['challenge'])
        authenticated = authenticator(get_config(), 
                                      decoded_user, 
                                      plaintext_auth['password'])

        if not challenge or not authenticated:
            log.info("Auth failed for %s" % (decoded_user,))
            return Forbidden()(environ, start_response)

        log.info("Auth OK for brand %s with user %s" % (brand_identifier, decoded_user, ))
        return fun(environ, start_response, decoded_user, plaintext_auth)
    return decorator

@read_querydata
@login_required
def authenticate_user(environ, start_response, username, auth):
    return SuperSimple("OK")(environ, start_response)

def create_secret_box(password, username):
    key = bcrypt.kdf(
        password.encode('utf-8'),
        username,                # this is the salt
        KEYLEN, ITERATIONS
    )
    
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return nacl.secret.SecretBox(key), nonce

@read_querydata
@read_postdata
@login_required
def read_data(environ, start_response, username, auth):
    log = logging.getLogger("read_data")

    log.debug("start")
    try:
        brand_identifier = environ['query_data']['brand_id'][0]
        escrowed_data = environ['post_data']['escrow_data'][0]
        serial_sign_key = environ['post_data']['sign_key'][0]
    except KeyError:
        log.warn("KeyError at start")
        return BadRequest()(environ, start_response)

    try:
        layer_count = int(environ['post_data'].get('layer_count', [])[0])
    except IndexError:
        layer_count = None
    
    sign_key = serial.loads(serial_sign_key)
    log.debug("Being sent:")
    log.debug("brand_identifier: %r" % brand_identifier)
    log.debug("layer_count: %r" % layer_count)

    try:
        if layer_count is None:
            plaintext_data = server.read_escrow_data(brand_identifier, 
                                                     escrowed_data, 
                                                     sign_key=sign_key)
        else:
            plaintext_data = server.read_escrow_data(brand_identifier, 
                                                     escrowed_data,
                                                     layer_count=layer_count,
                                                     sign_key=sign_key)
    except ValueError:
        log.warn("ValueError at reading escrow data")
        return BadRequest()(environ, start_response)
    except KeyError:
        log.warn("KeyError at reading escrow data")
        return NotFound()(environ, start_response)
    except Exception:
        log.exception('500 error in reading escrow data')
        return ServerError()(environ, start_response,)

    secret_box, nonce = create_secret_box(auth['password'], SESSION[username][0])
    response = secret_box.encrypt(plaintext_data, nonce)
    plain = secret_box.decrypt(response)

    log.info("Read data for brand %s" % (brand_identifier,))
    return SuperSimple(response, ctype="application/octet-stream")(environ, start_response)

def app_factory(environ, start_response):
    # rx, methods, app
    urls = [
        (re.compile(r'/authsession$'), ('GET', 'HEAD',), start_auth_session),
        (re.compile(r'/auth$'), ('GET', 'HEAD',), authenticate_user),
        (re.compile(r'/data$'), ('POST'), read_data),
    ] 
    return router(urls)(environ, start_response)
