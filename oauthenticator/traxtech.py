"""
Custom Authenticator to use Trax OAuth with JupyterHub.

Derived from the Google OAuth authenticator.
"""

import os
import json

from tornado             import gen
from tornado.auth        import OAuth2Mixin
from tornado.web         import HTTPError

from traitlets           import Unicode

from jupyterhub.auth     import LocalAuthenticator
from jupyterhub.utils    import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator

class TraxOAuth2Mixin(OAuth2Mixin):
    """Trax Technologies authentication using OAuth2.

    Addapted from TraxOAuth2Mixin
    https://github.com/tornadoweb/tornado/blob/master/tornado/auth.py#L833
    """
    _OAUTH_AUTHORIZE_URL = "https://auth.traxtech.com/oauth2/auth""
    _OAUTH_ACCESS_TOKEN_URL = "https:///auth.traxtech.com/auth2/token"
    _OAUTH_USERINFO_URL = "https://auth.traxtech.com/userinfo"
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'trax_oauth'

    @_auth_return_future
    def get_authenticated_user(self, redirect_uri, code, callback):
        """Handles the login for the Trax user, returning an access token.
        """
        http = self.get_auth_http_client()
        body = urllib_parse.urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "grant_type": "authorization_code",
        })

        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
                   functools.partial(self._on_access_token, callback),
                   method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)

    def _on_access_token(self, future, response):
        """Callback function for the exchange to the access token."""
        if response.error:
            future.set_exception(AuthError('Trax auth error: %s' % str(response)))
            return

        args = escape.json_decode(response.body)
        future.set_result(args)


class TraxLoginHandler(OAuthLoginHandler, TraxOAuth2Mixin):
    '''An OAuthLoginHandler that provides scope to TraxOAuth2Mixin's
       authorize_redirect.'''
    def get(self):
        guess_uri = '{proto}://{host}{path}'.format(
            proto=self.request.protocol,
            host=self.request.host,
            path=url_path_join(
                self.hub.server.base_url,
                'oauth_callback'
            )
        )

        redirect_uri = self.authenticator.oauth_callback_url or guess_uri
        self.log.info('redirect_uri: %r', redirect_uri)

        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=['openid', 'email'],
            response_type='code')

class TraxOAuthHandler(OAuthCallbackHandler, TraxOAuth2Mixin):
    @gen.coroutine
    def get(self):
        self.settings['trax_oauth'] = {
            'key': self.authenticator.client_id,
            'secret': self.authenticator.client_secret,
            'scope': ['openid', 'email']
        }
        self.log.debug('google: settings: "%s"', str(self.settings['google_oauth']))
        # FIXME: we should verify self.settings['google_oauth']['hd']

        # "Cannot redirect after headers have been written" ?
        #OAuthCallbackHandler.get(self)
        username = yield self.authenticator.get_authenticated_user(self, None)
        self.log.info('google: username: "%s"', username)
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error
            raise HTTPError(403)

class TraxOAuthenticator(OAuthenticator, TraxOAuth2Mixin):

    login_handler = TraxLoginHandler
    callback_handler = TraxOAuthHandler

    hosted_domain = Unicode(
        os.environ.get('HOSTED_DOMAIN', ''),
        config=True,
        help="""Hosted domain used to restrict sign-in, e.g. mycollege.edu"""
    )
    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Trax'),
        config=True,
        help="""Trax Apps hosted domain string, e.g. My College"""
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument('code', False)
        if not code:
            raise HTTPError(400, "oauth callback made without a token")
        if not self.oauth_callback_url:
            raise HTTPError(500, "No callback URL")
        user = yield handler.get_authenticated_user(
            redirect_uri=self.oauth_callback_url,
            code=code)
        access_token = str(user['access_token'])

        http_client = handler.get_auth_http_client()

        response = yield http_client.fetch(
            self._OAUTH_USERINFO_URL + '?access_token=' + access_token
        )

        if not response:
            self.clear_all_cookies()
            raise HTTPError(500, 'Trax authentication failed')

        body = response.body.decode()
        self.log.debug('response.body.decode(): {}'.format(body))
        bodyjs = json.loads(body)

        username = bodyjs['email']

        if self.hosted_domain:
            if not username.endswith('@'+self.hosted_domain) or \
                bodyjs['hd'] != self.hosted_domain:
                raise HTTPError(403,
                    "You are not signed in to your {} account.".format(
                        self.hosted_domain)
                )
            else:
                username = username.split('@')[0]

        return username

class LocalTraxOAuthenticator(LocalAuthenticator, TraxOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
