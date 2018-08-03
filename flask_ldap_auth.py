#!/usr/bin/env python
# encoding: utf-8

from functools import wraps
from flask import Blueprint, current_app, jsonify, Response, request, url_for
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature, SignatureExpired
from ldap3 import Server, Connection, NTLM, SUBTREE
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
        else:
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
        try:
            auth = request.headers['X-API-KEY']
        except KeyError:
            return authenticate()

        if not auth or not User.verify_auth_token(request.headers['X-API-KEY']):
            return authenticate()
        return func(*args, **kwargs)
    return wrapper


def auth_user(user):
    server = Server(current_app.config['LDAP_AUTH_SERVER'])
    conn = Connection(server, user=current_app.config['LDAP_SERVICE_USER'], password=current_app.config['LDAP_SERVICE_USER_PASSWORD'], authentication=NTLM, auto_bind=True)
    conn.bind()

    conn.search(search_base=current_app.config['LDAP_TOP_DN'],
                search_filter='(&(objectClass=person)(memberOf=' + current_app.config['LDAP_API_SECURITY_GROUP_CN'] + '))',
                search_scope=SUBTREE,
                attributes=['sAMAccountName'], size_limit=0)
    results = conn.entries

    conn.unbind()

    for result in results:
        for username in result:
            if str(username).lower() == str(user).lower():
                return True

    # else return false
    return False


@token.route('/request-token', methods=['POST'])
def request_token():
    """Simple app to generate a token"""
    auth = request.authorization
    user = User(auth.username)
    # verify user password and check whether user is authorized to use the API
    if not auth or not user.verify_password(auth.password) or not auth_user(str.split(User(auth.username).username, '\\')[1]):
        return authenticate()
    response = {
        'token': user.generate_auth_token()
        }
    return jsonify(response)

# EOF