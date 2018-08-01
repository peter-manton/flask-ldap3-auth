#!/usr/bin/env python
# encoding: utf-8

from functools import wraps
from flask import Blueprint, current_app, jsonify, Response, request, url_for
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired
from ldap3 import Server, Connection, NTLM
from ldap3.core.exceptions import LDAPException, LDAPBindError
import json


token = Blueprint('token', __name__)


__all__ = [
    'login_required',
    'token'
    ]


class User(object):

    def __init__(self, username):
        self.username = username

    def verify_password(self, password):
        try:
            server = Server(current_app.config['LDAP_AUTH_SERVER'])
            conn = Connection(server, user=self.username, password=password, authentication=NTLM, auto_bind=True)
            conn.bind()
        except LDAPBindError:
            print('Error: Unable to authenticate user.')
            return False
        except LDAPException as err:
            print('Error: ' + str(err))
            return False
        else:
            conn.unbind()
            return True


    def generate_auth_token(self):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=3600)
        return s.dumps({'username': self.username}).decode('utf-8')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except (BadSignature, SignatureExpired, TypeError):
            return None
        return User(data['username'])


def authenticate():
    message = {
        'error': 'unauthorized',
        'message': 'Please authenticate with a valid token',
        'status': 401
        }
    response = Response(
        json.dumps(message),
        401,
        {
            'WWW-Authenticate': 'Basic realm="Authentication Required"',
            'Location': url_for('token.request_token')
            }
        )
    return response


def login_required(func):
    """LDAP authentication decorator"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or not User.verify_auth_token(auth.username):
            return authenticate()
        return func(*args, **kwargs)
    return wrapper


@token.route('/request-token', methods=['POST'])
def request_token():
    """Simple app to generate a token"""
    auth = request.authorization
    user = User(auth.username)
    print(auth.username)
    if not auth or not user.verify_password(auth.password):
        return authenticate()
    response = {
        'token': user.generate_auth_token() + ':'
        }
    return jsonify(response)

# EOF