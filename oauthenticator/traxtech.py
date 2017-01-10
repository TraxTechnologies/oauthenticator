"""
Custom Authenticator to use Trax OAuth with JupyterHub.

Derived from the Google OAuth authenticator.
"""

import os
import json
import functools

from tornado             import gen
from tornado.auth        import (
                            OAuth2Mixin,
                            _auth_return_future,
                            urllib_parse,
                            AuthError,
                            escape)
from tornado.web         import HTTPError
from tornado.concurrent import TracebackFuture, return_future, chain_future

from traitlets           import Unicode

from jupyterhub.auth     import LocalAuthenticator
from jupyterhub.utils    import url_path_join
from tornado.httputil import url_concat

from .oauth2 import OAuthLoginHandler, OAuthCallbackHandler, OAuthenticator

DEFAULT_OAUTH_AUTHORIZE_URL = 'https://auth.traxtech.com/oauth2/auth'
DEFAULT_OAUTH_ACCESS_TOKEN_URL = 'https://auth.traxtech.com/oauth2/token'
DEFAULT_OAUTH_USERINFO_URL = 'https://auth.traxtech.com/userinfo'


class TraxOAuth2Mixin(object):
    """Abstract implementation of OAuth 2.0.

    See `FacebookGraphMixin` or `GoogleOAuth2Mixin` below for example
    implementations.
    """

    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'trax_oauth'

    _CONF_OBJ = None

    @property
    def _oauth_authorize_url(self):
        return getattr(
            self._CONF_OBJ,
            'oauth_authorize_url',
            os.environ.get('OAUTH_AUTHORIZE_URL', DEFAULT_OAUTH_AUTHORIZE_URL),
        )

    @property
    def _oauth_access_token_url(self):
        return getattr(
            self._CONF_OBJ,
            'oauth_access_token_url',
            os.environ.get('OAUTH_ACCESS_TOKEN_URL', DEFAULT_OAUTH_ACCESS_TOKEN_URL),
        )

    @property
    def _oauth_userinfo_url(self):
        return getattr(
            self._CONF_OBJ,
            'oauth_userinfo_url',
            os.environ.get('OAUTH_USERINFO_URL', DEFAULT_OAUTH_USERINFO_URL),
        )

    @return_future
    def authorize_redirect(self, redirect_uri=None, client_id=None,
                           client_secret=None, extra_params=None,
                           callback=None, scope=None, response_type="code"):
        """Redirects the user to obtain OAuth authorization for this service.

        Some providers require that you register a redirect URL with
        your application instead of passing one via this method. You
        should call this method to log the user in, and then call
        ``get_authenticated_user`` in the handler for your
        redirect URL to complete the authorization process.

        .. versionchanged:: 3.1
           Returns a `.Future` and takes an optional callback.  These are
           not strictly necessary as this method is synchronous,
           but they are supplied for consistency with
           `OAuthMixin.authorize_redirect`.
        """
        args = {
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "response_type": response_type
        }
        if extra_params:
            args.update(extra_params)
        if scope:
            args['scope'] = ' '.join(scope)
        self.redirect(
            url_concat(self._oauth_authorize_url, args))
        callback()

    def _on_access_token(self, future, response):
        """Callback function for the exchange to the access token."""
        if response.error:
            future.set_exception(AuthError('Trax auth error: %s' % str(response)))
            return

        args = escape.json_decode(response.body)
        future.set_result(args)

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

        http.fetch(self._oauth_access_token_url,
                   functools.partial(self._on_access_token, callback),
                   method="POST", headers={'Content-Type': 'application/x-www-form-urlencoded'}, body=body)


    def _oauth_request_token_url(self, redirect_uri=None, client_id=None,
                                 client_secret=None, code=None,
                                 extra_params=None):
        url = self._oauth_access_token_url
        args = dict(
            redirect_uri=redirect_uri,
            code=code,
            client_id=client_id,
            client_secret=client_secret,
        )
        if extra_params:
            args.update(extra_params)
        return url_concat(url, args)

    @_auth_return_future
    def oauth2_request(self, url, callback, access_token=None,
                       post_args=None, **args):
        """Fetches the given URL auth an OAuth2 access token.

        If the request is a POST, ``post_args`` should be provided. Query
        string arguments should be given as keyword arguments.

        Example usage:

        ..testcode::

            class MainHandler(tornado.web.RequestHandler,
                              tornado.auth.FacebookGraphMixin):
                @tornado.web.authenticated
                @tornado.gen.coroutine
                def get(self):
                    new_entry = yield self.oauth2_request(
                        "https://graph.facebook.com/me/feed",
                        post_args={"message": "I am posting from my Tornado application!"},
                        access_token=self.current_user["access_token"])

                    if not new_entry:
                        # Call failed; perhaps missing permission?
                        yield self.authorize_redirect()
                        return
                    self.finish("Posted a message!")

        .. testoutput::
           :hide:

        .. versionadded:: 4.3
        """
        all_args = {}
        if access_token:
            all_args["access_token"] = access_token
            all_args.update(args)

        if all_args:
            url += "?" + urllib_parse.urlencode(all_args)
        callback = functools.partial(self._on_oauth2_request, callback)
        http = self.get_auth_http_client()
        if post_args is not None:
            http.fetch(url, method="POST", body=urllib_parse.urlencode(post_args),
                       callback=callback)
        else:
            http.fetch(url, callback=callback)

    def _on_oauth2_request(self, future, response):
        if response.error:
            future.set_exception(AuthError("Error response %s fetching %s" %
                                           (response.error, response.request.url)))
            return

        future.set_result(escape.json_decode(response.body))

    def get_auth_http_client(self):
        """Returns the `.AsyncHTTPClient` instance to be used for auth requests.

        May be overridden by subclasses to use an HTTP client other than
        the default.

        .. versionadded:: 4.3
        """
        return httpclient.AsyncHTTPClient()


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
        self.log.info('redirect_uri: %r %s', redirect_uri, self.authenticator.client_id)

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
        self.log.debug('trax: settings: "%s"', str(self.settings['trax_oauth']))
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

    def __init__(self, *args, **kwargs):
        super(OAuthenticator, self).__init__(*args, **kwargs)
        TraxOAuth2Mixin._CONF_OBJ = self

    login_handler = TraxLoginHandler
    callback_handler = TraxOAuthHandler

    hosted_domain = Unicode(
        os.environ.get('HOSTED_DOMAIN', ''),
        config=True,
        help="""Hosted domain used to restrict sign-in, e.g. mycollege.edu"""
    )
    login_service = Unicode(
        os.environ.get('LOGIN_SERVICE', 'Trax'),
        help="""Trax Apps hosted domain string, e.g. My College"""
    ).tag(config=True)
    oauth_authorize_url = Unicode(
        os.environ.get('OAUTH_AUTHORIZE_URL', DEFAULT_OAUTH_AUTHORIZE_URL),
        config=True,
        help="""OAuth2 Authorization url"""
    ).tag(config=True)
    oauth_access_token_url = Unicode(
        os.environ.get('OAUTH_ACCESS_TOKEN_URL', DEFAULT_OAUTH_ACCESS_TOKEN_URL),
        help="""OAuth2 Access Token url"""
    ).tag(config=True)
    oauth_userinfo_url = Unicode(
        os.environ.get('OAUTH_USERINFO_URL', DEFAULT_OAUTH_USERINFO_URL),
        help="""OAuth2 user info url"""
    ).tag(config=True)

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
            self._oauth_userinfo_url,
            method='POST', body=urllib_parse.urlencode({
                'access_token': access_token
            })
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
