"""
Vinli Authentication for tornado

The following is heavily based on Google/Facebook/Twitter/etc
authentication in the core Tornado auth module.

https://github.com/tornadoweb/tornado/blob/master/tornado/auth.py
"""
import base64
import functools
import sys
import tornado.auth

from tornado.concurrent import chain_future

if sys.version_info >= (3, 0):
    import urllib.parse as urlparse
    import urllib.parse as urllib_parse
else:
    import urlparse
    import urllib as urllib_parse


class VinliAuthLoginMixin(tornado.auth.OAuth2Mixin):
    """
    Mixin to authenticate and perform authenticated requests to the
    Vinli platform
    """
    _OAUTH_AUTHORIZE_URL = 'https://auth.vin.li/oauth/authorization/new'
    _OAUTH_ACCESS_TOKEN_URL = 'https://auth.vin.li/oauth/token'
    _OAUTH_USERINFO_URL = 'https://auth.vin.li/api/v1/users/_current'
    _OAUTH_NO_CALLBACKS = False

    _VINLI_BASE_URL = '.vin.li'

    @tornado.auth._auth_return_future
    def get_authenticated_user(self, redirect_uri, code, callback):
        """
        Do the oauth dance with the Vinli platform.
        """
        http = self.get_auth_http_client()
        args = urllib_parse.urlencode({
            'redirect_uri': redirect_uri,
            'code': code,
            'grant_type': 'authorization_code'
        })

        creds = '{}:{}'.format(
            self.settings.get('vinli_client_id'),
            self.settings.get('vinli_client_secret')
        )

        headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic {}'.format(
                base64.b64encode(creds.encode('ascii')))
        }

        http.fetch(
            self._OAUTH_ACCESS_TOKEN_URL,
            functools.partial(self._on_access_token, callback),
            method='POST', body=args,
            headers=headers
        )

    def _on_access_token(self, future, response):
        """
        Callback after the access token is obtained
        """
        if response.error:
            future.set_exception(
                tornado.auth.AuthError(
                    "Vinli Auth Error: {}".format(response)
                )
            )
            return

        args = tornado.escape.json_decode(response.body)
        future.set_result(args)

    @tornado.auth._auth_return_future
    def oauth2_request(self, url, callback, access_token=None,
                       post_args=None, **kwargs):
        """
        Based on ``oauth2_request`` in ``tornado.auth``, however
        instead of sending the access_token as a query param,
        an Authorization header is sent.
        """
        all_args = {}
        headers = {
            'Authorization': 'Bearer {}'.format(access_token)
        }

        if all_args:
            url += "?" + urllib_parse.urlencode(all_args)
        callback = functools.partial(self._on_oauth2_request, callback)
        http = self.get_auth_http_client()
        if post_args is not None:
            http.fetch(url, method="POST",
                       body=urllib_parse.urlencode(post_args),
                       callback=callback, headers=headers)
        else:
            http.fetch(url, callback=callback, headers=headers)

    @tornado.auth._auth_return_future
    def vinli_request(self, service, path, callback,
                      access_token=None, post_args=None, **kwargs):
        """
        Make an authenticated request to the vinli platform.
        """
        url = 'https://{}{}{}'.format(
            service, self._VINLI_BASE_URL, path
        )

        oauth_future = self.oauth2_request(url, access_token=access_token,
                                           post_args=post_args, **kwargs)
        chain_future(oauth_future, callback)
