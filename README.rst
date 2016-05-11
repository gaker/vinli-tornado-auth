==================
Vinli Tornado Auth
==================

`Vinli <https://www.vin.li/>`_ platform auth wrapper for `Tornado <http://www.tornadoweb.org>`_ 

------------
Installation
------------

::

    pip install vinli-tornado-auth

---------------------
Settings Requirements
---------------------

Register and create an app at `https://dev.vin.li <dev.vin.li>`_

In the app, create a ``web`` client type and take note of the 
following values:

* ``vinli_client_id`` - App Client Id
* ``vinli_client_secret`` - App Client Secret
* ``vinli_redirect_uri`` - A valid URL to redirect to. eg: ``http://localhost:8000/auth/login``

Add these values to application ``settings``.

-------------
Example Usage
-------------

::
    
    import tornado.escape
    import tornado.ioloop
    import tornado.gen
    import tornado.web

    from vinli_tornado_auth.auth import VinliAuthLoginMixin

    class LoginHandler(tornado.web.RequestHandler, VinliAuthLoginMixin):
        """
        Handle /auth/login
        """
        @tornado.gen.coroutine
        def get(self):
            code = self.get_argument('code', None)
            if not code:
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


-----------------------------
Making Authenticated Requests
-----------------------------

Use the ``vinli_request`` method to make authenticated requests to
the platform after initial authentication has been completed.

Get Trips for a device
^^^^^^^^^^^^^^^^^^^^^^

As with the `following example <http://docs.vin.li/en/latest/web/trip-services/index.html>`_
from the Vinli API Documentation, a list of trips for device id
``fe4bbc20-cc90-11e3-8e05-f3abac5b6b58`` can be retrieved with the following::

    @tornado.web.authenticated
    @tornado.gen.coroutine
    def get(self):
        trips = yield self.vinli_request(
            'trips', '/api/v1/devices/fe4bbc20-cc90-11e3-8e05-f3abac5b6b58/trips',
            access_token=self.current_user.get('token')
        )
        self.write(trips)
