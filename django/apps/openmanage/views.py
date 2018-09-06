import logging
import os
import re
import nacl.secret
import bcrypt
import json
from binascii import b2a_base64, a2b_base64
import time

from django.views.decorators.csrf import csrf_exempt
from django.utils.crypto import constant_time_compare
from django.http import (
    HttpResponse, HttpResponseForbidden, HttpResponseBadRequest,
    HttpResponseNotFound, HttpResponseServerError
)
from django.shortcuts import get_object_or_404

import urllib

from common import read_config_file, validate_config
from account_mgr import authenticator
from key_escrow import server
from Pandora import serial
from netkes.account_mgr.user_source import local_source

from openmanage import models

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
    config = read_config_file()
    validate_config(config)


setup_logging()
setup_application()
serial.register_all()

@csrf_exempt
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
            authenticated = authenticator(read_config_file(),
                                        decoded_user,
                                        plaintext_auth['password'])

            if not challenge or not authenticated:
                log.info("Auth failed for %s" % (decoded_user,))
                return HttpResponseForbidden()

            session_challenge = get_challenge(request)
            secret_box, nonce = create_secret_box(plaintext_auth['password'],
                                                  session_challenge[0])
            request.session['auth'] = {
                'secret_box': secret_box,
                'nonce': nonce,
                'time': session_challenge[1],
                'brand_identifier': brand_identifier,
                'sign_key': sign_key,
                'layer_count': layer_count,
            }

            log.info("Auth OK for brand %s with user %s" % (brand_identifier, decoded_user, ))
            return fun(request)
    return decorator

@csrf_exempt
@login_required
def authenticate_user(request):
    return HttpResponse('OK')

def create_secret_box(password, username):
    key = bcrypt.kdf(
        password.encode('utf-8'),
        username,                # this is the salt
        KEYLEN, ITERATIONS
    )

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return nacl.secret.SecretBox(key), nonce

@csrf_exempt
@login_required
def read_data(request):
    log = logging.getLogger("read_data")

    log.debug("start")
    auth = request.session['auth']
    brand_identifier = auth['brand_identifier']
    sign_key = auth['sign_key']
    layer_count = auth['layer_count']

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
        log.warn("ValueError at reading escrow data", exc_info=True)
        return HttpResponseBadRequest()
    except KeyError:
        log.warn("KeyError at reading escrow data", exc_info=True)
        return HttpResponseNotFound()
    except Exception:
        log.exception('500 error in reading escrow data', exc_info=True)
        return HttpResponseServerError()

    response = auth['secret_box'].encrypt(plaintext_data, auth['nonce'])

    log.info("Read data for brand %s" % (brand_identifier,))
    return HttpResponse(response, content_type="application/octet-stream")


@csrf_exempt
def password(request):
    log = logging.getLogger('password')
    config = read_config_file()
    minimum_password_length = config.get('minimum_password_length', 8)

    if request.method == 'POST':
        try:
            email = request.POST['email']
            new_password = request.POST['password']
        except KeyError:
            log.error("Got bad request. Missing arguments.")
            return HttpResponse()
        if len(new_password) < minimum_password_length:
            message = 'Password too short. It should be at least {} characters long'.format(
                minimum_password_length
            )
            log.warning(message)
            return HttpResponseServerError(
                content=message,
                content_type='text/plain',
            )
        try:
            password = models.Password.objects.get(pk=email)
        except models.Password.DoesNotExist:
            log.error("Password not found for user")
            return HttpResponse()

        if password.password_set():
            log.error("Cannot set password. Password already set.")
            return HttpResponse()

        password.pw_hash = new_password
        password.save()

        return HttpResponse()
