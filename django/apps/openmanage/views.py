import logging
import os
import re
import nacl.secret
import bcrypt
import json
from binascii import b2a_base64, a2b_base64
import time

from django.utils.crypto import constant_time_compare
from django.http import (
    HttpResponse, HttpResponseForbidden, HttpResponseBadRequest, 
    HttpResponseNotFound, HttpResponseServerError
)

import urllib
from wsgi_util.router import router
from wsgi_util.http import BadRequest, SuperSimple, NotFound, Forbidden, ServerError
from wsgi_util.post_util import read_postdata, read_querydata

from common import get_config, read_config_file, set_config, validate_config, NetKesConfigError
from account_mgr import authenticator
from key_escrow import server
from Pandora import serial

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

def start_auth_session(request):
    log = logging.getLogger("get_layers")

    log.debug("start")
    try:
        brand_identifier = request.POST['brand_id']
    except KeyError:
        log.error("Got bad request.")
        return HttpResponseBadRequest()

    challenge = b2a_base64(os.urandom(32))
    request.session['challenge'] = (challenge, time.time())
    auth = request.session.get('auth', False)
    if auth:
        del request.session['auth']

    try:
        layer_data = server.get_escrow_layers(brand_identifier)
    except (KeyError, IOError,):
        log.warn("Got missing brand_identifier: %s" % (brand_identifier,))
        return HttpResponseNotFound()

    log.info("Returning escrow keys for %s" % (brand_identifier,))

    data = dict(layer_data=b2a_base64(layer_data),
                challenge=challenge)

    return HttpResponse(json.dumps(data))

def active_challenge(session_challenge):
    if not session_challenge:
        return False
    if session_challenge[1] + CHALLENGE_EXPIRATION_TIME < time.time(): 
        return False
    return True

def valid_challenge(request, challenge):
    session_challenge = request.session.get('challenge', False)

    if active_challenge(session_challenge):
        return constant_time_compare(session_challenge[0], challenge)
    return False

def valid_auth_session(request):
    session_challenge = request.session.get('challenge', False)

    if active_challenge(session_challenge):
        auth = request.session.get('auth', False)
        if auth:
            return auth['time'] + CHALLENGE_EXPIRATION_TIME > time.time()
    return False
    
def get_challenge(request):
    return request.session['challenge']

def login_required(fun):
    def decorator(request):
        log = logging.getLogger('login_required')
        log.debug("start")
        if valid_auth_session(request):
            return fun(request)
        else:
            try:
                brand_identifier = request.POST['brand_id']
                username = request.POST['username']
                auth = a2b_base64(request.POST['auth'])
                serial_sign_key = request.POST['sign_key']
                layer_count = int(request.POST['layer_count'])
            except KeyError:
                log.error("Got bad request.")
                return HttpResponseBadRequest()

            try:
                sign_key = serial.loads(serial_sign_key)
            except (serial.EndOfFile, 
                    serial.NotSerializerFileError, 
                    serial.NotSerializableObjectError):
                log.error("Got bad request. Unable to load sign key")
                return HttpResponseBadRequest()

            decoded_user = urllib.unquote(username)

            try:
                data =  server.read_escrow_data(
                    brand_identifier, 
                    auth, 
                    sign_key=sign_key, 
                    layer_count=layer_count,
                )

                plaintext_auth = json.loads(data)
                if ('challenge' not in plaintext_auth or 
                    'password' not in plaintext_auth):
                    log.warn("missing auth key %s" % (brand_identifier,))
                    return HttpResponseBadRequest()
            except KeyError:
                log.warn("missing identifier %s" % (brand_identifier,))
                return HttpResponseNotFound()
            except ValueError:
                log.warn("bad values for authenticating user %s" % (decoded_user,))
                return HttpResponseBadRequest()
            except Exception:
                log.exception("server.read_escrow_data failed for user %s brand %s"
                        % (decoded_user, brand_identifier,))
                return HttpResponseServerError()

            challenge = valid_challenge(request, plaintext_auth['challenge'])
            authenticated = authenticator(get_config(), 
                                        decoded_user, 
                                        plaintext_auth['password'])

            if not challenge or not authenticated:
                log.info("Auth failed for %s" % (decoded_user,))
                return HttpResponseForbidden()

            session_challenge = get_challenge(request)
            secret_box = create_secret_box(plaintext_auth['password'],
                                           a2b_base64(session_challenge[0]))
            request.session['auth'] = {
                'secret_box': secret_box,
                'time': session_challenge[1],
                'brand_identifier': brand_identifier,
                'sign_key': sign_key,
                'layer_count': layer_count,
            }

            log.info("Auth OK for brand %s with user %s" % (brand_identifier, decoded_user, ))
            return fun(request)
    return decorator

@login_required
def authenticate_user(request):
    return HttpResponse('OK')

def create_secret_box(password, salt):
    key = bcrypt.kdf(password.encode('utf-8'), salt, KEYLEN, ITERATIONS)
    return nacl.secret.SecretBox(key)

@login_required
def read_data(request):
    log = logging.getLogger("read_data")

    log.debug("start")
    auth = request.session['auth']
    brand_identifier = auth['brand_identifier']

    serial_sign_key = auth.get('sign_key')
    if serial_sign_key:
        try:
            sign_key = serial.loads(serial_sign_key)
        except (serial.EndOfFile, 
                serial.NotSerializerFileError, 
                serial.NotSerializableObjectError):
            log.error("Got bad request. Unable to load sign key")
            return HttpResponseBadRequest()

    try:
        layer_count = int(auth.get('layer_count', 2))
    except ValueError:
        log.warn("ValueError at layer_count")
        return HttpResponseBadRequest()

    try:
        escrowed_data = a2b_base64(request.POST['escrow_data'])
    except KeyError:
        log.warn("KeyError at start")
        return HttpResponseBadRequest()

    log.debug("Being sent:")
    log.debug("brand_identifier: %r" % brand_identifier)
    log.debug("layer_count: %r" % layer_count)

    try:
        plaintext_data = server.read_escrow_data(brand_identifier, 
                                                 escrowed_data,
                                                 layer_count=layer_count,
                                                 sign_key=sign_key)
    except ValueError:
        log.warn("ValueError at reading escrow data")
        return HttpResponseBadRequest()
    except KeyError:
        log.warn("KeyError at reading escrow data")
        return HttpResponseNotFound()
    except Exception:
        log.exception('500 error in reading escrow data')
        return HttpResponseServerError()

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    response = auth['secret_box'].encrypt(plaintext_data, nonce)

    log.info("Read data for brand %s" % (brand_identifier,))
    return HttpResponse(response, content_type="application/octet-stream")
