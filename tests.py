"""
Based on tests at

    https://github.com/tornadoweb/tornado/blob/master/tornado/test/auth_test.py

As is mentioned there, this is merely meant to catch potential syntax
errors, or python 2/3 errors.
"""


import tornado.gen

from tornado.escape import json_decode
from tornado.httputil import url_concat
from tornado.web import Application, RequestHandler
from tornado.testing import AsyncHTTPTestCase


from vinli_tornado_auth.auth import VinliAuthLoginMixin


class VinliLoginHandler(RequestHandler, VinliAuthLoginMixin):

    def initialize(self, test):
        self.test = test
        self._OAUTH_AUTHORIZE_URL = test.get_url('/oauth/authorization/new')
        self._OAUTH_ACCESS_TOKEN_URL = test.get_url('/oauth/token')
        self._OAUTH_USERINFO_URL = test.get_url('/api/v1/users/_current')

    @tornado.gen.coroutine
    def get(self):
        code = self.get_argument('code', None)
        if not code:
            yield self.authorize_redirect(
                redirect_uri=self.request.full_url(),
                client_id=self.settings['vinli_client_id'],
                response_type='code'
            )
        else:
            access = yield self.get_authenticated_user(
                redirect_uri=self.request.full_url(),
                code=code
            )
            user = yield self.oauth2_request(
                self._OAUTH_USERINFO_URL,
                access_token=access['access_token']
            )
            self.write(user)


class VinliOAuth2AuthorizeHandler(RequestHandler):
    def get(self):
        self.redirect(
            url_concat(self.get_argument('redirect_uri'),
            dict(code='some-fake-code')))


class VinliOAuth2TokenHandler(RequestHandler):
    def post(self):
        assert self.get_argument('code') == 'some-fake-code'
        self.finish({
            'access_token': 'abc123',
            'expires': 'nope'
        })


class VinliOAuth2UserinfoHandler(RequestHandler):
    def get(self):
        assert self.request.headers['authorization'] == 'Bearer abc123'
        self.finish({
            'user': {
                'name': 'foobar'
            }
        })


class VinliAuthTestsCase(AsyncHTTPTestCase):
    def get_app(self):
        settings = {
            'vinli_redirect_uri': 'http://example.com/auth/login',
            'vinli_client_id': 'abc123',
            'vinli_client_secret': 'secret!'
        }

        return Application([
            ('/vinli/auth/login', VinliLoginHandler, dict(test=self)),

            # mocked handlers
            ('/oauth/authorization/new', VinliOAuth2AuthorizeHandler),
            ('/oauth/token', VinliOAuth2TokenHandler),
            ('/api/v1/users/_current', VinliOAuth2UserinfoHandler),

        ],
        **settings)


    def test_vinli_login(self):
        response = self.fetch('/vinli/auth/login')
        self.assertEqual(response.code, 200)
        self.assertDictEqual(
            {"user": {"name": "foobar"}},
            json_decode(response.body)
        )
