==================
Vinli Tornado Auth
==================

`Vinli <https://www.vin.li/>`_ platform auth wrapper for `Tornado <http://www.tornadoweb.org>`_ 

------------
Installation
------------

::

    pip install vinli-tornado-auth

-------------
Example Usage
-------------

::
    
    import tornado.escape
    import tornado.ioloop
    import tornado.gen
    import tornado.web

    from vinli_tornado_auth import VinliAuthLoginMixin

    class LoginHandler(tornado.web.RequestHandler, VinliAuthLoginMixin):
        """
        Handle /auth/login
        """
        @tornado.gen.coroutine
        def get(self):
            code = self.get_argument('code', None)
            if note code:
                yield self.authorize_redirect(
                    redirect_uri=self.settings['vinli_redirect_uri'],
                    client_id=self.settings['vinli_client_id'],
                    response_type='code'
                )
            else:
                access = yield self.get_authenticated_user(
                    redirect_uri=self.settings['vinli_redirect_uri'],
                    code=code
                )
                user = yield self.oauth2_request(
                    self._OAUTH_USERINFO_URL,
                    access_token=access['access_token']
                )
                self.set_secure_cookie(
                    'user', tornado.escape.json_encode({
                        'user': user,
                        'token': access['access_token']
                    })
                )
                self.redirect('/')


    class IndexHandler(tornado.web.RequestHandler, VinliAuthLoginMixin):
        """
        Handle /
        """
        def get_current_user(self):
            user = self.get_secure_cookie('user')
            if not user:
                return None
            return tornado.escape.json_decode(user)

        @tornado.web.authenticated
        @tornado.gen.coroutine
        def get(self):
            devices = yield self.vinli_request(
                'platform', '/api/v1/devices',
                access_token=self.current_user.get('token')
            )
            self.write(devices)


    class Application(tornado.web.Application):
        def __init__(self):
            settings = {
                'vinli_client_id': 'abc123',
                'vinli_client_secret': "shhhh it is secret",
                'vinli_redirect_uri': 'http://localhost:8000/auth/login',
                'cookie_secret': '12345',
            }
            urls = [
                (r'/', IndexHandler),
                (r'/auth/login', LoginHandler),
            ]
            super(Application, self).__init__(urls, **settings)


    if __name__ == '__main__':
        app = Application()
        app.listen(8000)
        tornado.ioloop.IOLoop.instance().start()

