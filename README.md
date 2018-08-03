# Flask-LDAP3-Auth

Flask-LDAP3 is intended to be a simple Flask extension that allows you
to perform authentication against a LDAP server.

This version adds support for ldap3 i.e. if you are using python 3 or above - as the original only worked with < version 3.

The code is quite straight-forward, and can be hacked to implement other auth techniques.


## Requirements

 * Flask
 * pyldap

## Installation

Of course, the preferred way is via pip

```
$ pip install flask-ldap-auth
```

## New Features

 * Users are now authorized with an AD security group
 * The token is now passed via a custom HTTP header (rather than BASIC AUTH) - specifically X-API-KEY

## Usage

In you brand new Flask app (say `hello.py`), you can use flask-ldap like this:

```python

from flask_ldap3_auth import login_required, token, User
from flask_restplus import Resource, Api
from flask import Flask, request
from shlex import quote
import os, json

# define how we will authorize requests
authorizations = {
    'apikey' : {
        'type' : 'apiKey',
        'in' : 'header',
        'name' : 'X-API-KEY'
    }
}

app = Flask(__name__)
app.config['SECRET_KEY'] = """superstrongpassword"""
app.config['LDAP_AUTH_SERVER'] = 'ldap://127.0.0.1'
app.config['LDAP_TOP_DN'] = 'CN=Users,DC=yourdomain,DC=tld'
app.config['LDAP_SERVICE_USER'] = "yourdomain\\serviceuser"
app.config['LDAP_SERVICE_USER_PASSWORD'] = """superstrongpassword"""
app.config['LDAP_API_SECURITY_GROUP_CN'] = 'cn=API-USERS,cn=Users,DC=yourdomain,DC=tld'
app.register_blueprint(token, url_prefix='/auth')

api = Api(app, authorizations=authorizations)

# submits a job for processing
@api.route('/test')
class API_Test(Resource):
    @login_required
    @api.doc(security='apikey', params={'testparam': 'Test Parameter'})
    def post(self):
        user = str(User.verify_auth_token(request.headers['X-API-KEY']).username)
        return {'result': user}

if __name__ == '__main__':
    app.run()
```

Then serve it:

```
$ python hello.py
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)


```

Let's say you want to access the `/` endpoint. Using `httpie` you'll do:

```
$ http GET http://127.0.0.1:5000/
HTTP/1.0 401 UNAUTHORIZED
Content-Length: 93
Content-Type: text/html; charset=utf-8
Date: Thu, 16 Nov 2017 13:52:58 GMT
Location: http://127.0.0.1:5000/auth/request-token
Server: Werkzeug/0.12.2 Python/3.5.3
WWW-Authenticate: Basic realm="Authentication Required"

{
    "error": "unauthorized",
    "message": "Please authenticate with a valid token",
    "status": 401
}

```

See? It asks for a token, and points you to the right URL in order to get a valid one (see `Location` in the headers).

So to ask for a token, you must do:

```
$ http --auth your_username POST http://127.0.0.1:5000/auth/request-token
http: password for your_username@127.0.0.1:5000:
```

Type in your password (don't worry if nothing is displayed on-screen), and you'll received a shiny new token:

```
HTTP/1.0 200 OK
Content-Length: 189
Content-Type: application/json
Date: Thu, 16 Nov 2017 13:53:00 GMT
Server: Werkzeug/0.12.2 Python/3.5.3

{
    "token": "a_token:"
}
```

Now you can use this token and access the `/` endpoint:

```
$ TK='a_token:'
$ http --auth $TK GET http://127.0.0.1:5000/
HTTP/1.0 200 OK
Content-Length: 12
Content-Type: text/html; charset=utf-8
Date: Thu, 16 Nov 2017 13:53:10 GMT
Server: Werkzeug/0.12.2 Python/3.5.3

hello, world

```


## How it works

You may have noticed, in the above example, that we defined this:

```python
app.register_blueprint(token, url_prefix='/auth')
```

This means that, we provided the application  _flask_ldap.token_ under the uri `/auth` .


The fact is that `login_required` awaits a token for Basic HTTP Authentication. In other words, instead of passing (username, password) when authenticating you must pass (token,) .

That token is then verified (using the SECRET_KEY you've set in your app's config).

To obtain a token, you must pass (username, password) to the endpoint /auth/request-token. `username`and `password` are your actual LDAP credentials.

The obtained token is valid 1h.


