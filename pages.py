"""UI pages."""
import logging
from functools import wraps

from flask import flash, redirect, render_template, request
from google.cloud import ndb
from granary import as2
from granary.bluesky import Bluesky
from granary.mastodon import Mastodon
import oauth_dropins
import oauth_dropins.bluesky
import oauth_dropins.mastodon
import oauth_dropins.pixelfed
import oauth_dropins.threads
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import FlashErrors, get_required_param

from flask_app import app

logger = logging.getLogger(__name__)

# Cache-Control header for static files
CACHE_CONTROL = {'Cache-Control': 'public, max-age=3600'}  # 1 hour


def render(template, **vars):
    """Wrapper for Flask.render_template that populates common template vars."""
    if 'auths' not in vars:
        vars['auths'] = ndb.get_multi(oauth_dropins.get_logins())
    return render_template(template, **vars)


def require_login(fn):
    """Decorator that requires and loads the current request's logged in user.

    Passes the user in the ``user`` kwarg, as a :class:`models.User`.

    HTTP params:
      key (str): url-safe ndb key for an oauth-dropins auth entity
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = ndb.Key(urlsafe=get_required_param('auth_entity'))
        if key not in oauth_dropins.get_logins():
            logger.warning(f'not logged in for {key}')
            raise Found(location='/')

        return fn(*args, auth=key.get(), **kwargs)

    return wrapper


def granary_source(auth):
    """Returns a granary source instance for a given auth entity.

    Args:
      auth (oauth_dropins.models.BaseAuth)

    Returns:
      granary.source.Source:
    """
    if isinstance(auth, oauth_dropins.mastodon.MastodonAuth):
        return Mastodon(instance=auth.instance(), access_token=auth.access_token_str,
                        user_id=auth.user_id())
    elif isinstance(auth, oauth_dropins.bluesky.BlueskyAuth):
        return Bluesky(handle=auth.user_display_name(), did=auth.key.id(),
                       access_token=auth.dpop_token)


@app.get('/')
@flask_util.headers(CACHE_CONTROL)
def front_page():
    """View for the front page."""
    return render('index.html',
        bluesky_button=oauth_dropins.bluesky.Start.button_html(
            '/oauth/bluesky/start', image_prefix='/oauth_dropins_static/'),
        mastodon_button=oauth_dropins.mastodon.Start.button_html(
            '/oauth/mastodon/start', image_prefix='/oauth_dropins_static/'),
        pixelfed_button=oauth_dropins.pixelfed.Start.button_html(
            '/oauth/pixelfed/start', image_prefix='/oauth_dropins_static/'),
        threads_button=oauth_dropins.threads.Start.button_html(
            '/oauth/threads/start', image_prefix='/oauth_dropins_static/'),
    )


@app.get('/docs')
@flask_util.headers(CACHE_CONTROL)
def docs():
    """View for the docs page."""
    return render('docs.html')


@app.post('/logout')
def logout():
    """Logs the user out of all current login sessions."""
    oauth_dropins.logout()
    flash("OK, you're now logged out.")
    return redirect('/', code=302)


@app.get('/accounts')
def accounts():
    """User accounts page. Requires logged in session."""
    if not (logins := oauth_dropins.get_logins()):
        return redirect('/', code=302)

    return render('accounts.html')


@app.get('/review')
@require_login
def review(auth):
    """Review an account's followers and follows."""
    logger.info(f'Reviewing {auth.key.id()} {auth.user_display_name()}')

    source = granary_source(auth)

    logger.info('Fetching followers')
    followers = source.get_followers()

    logger.info('Fetching follows')
    follows = source.get_follows()

    if isinstance(auth, (oauth_dropins.mastodon.MastodonAuth,
                         oauth_dropins.pixelfed.PixelfedAuth,
                         oauth_dropins.threads.ThreadsAuth)):
        for f in followers + follows:
            f['username'] = as2.address(as2.from_as1(f))

    return render(
        'review.html',
        auth=auth,
        followers=followers,
        follows=follows,
    )


@app.get('/migrate')
@require_login
def migrate():
    """View for the migration preparation page."""
    auth = g.auth
    user_id = None
    handle = None
    platform = "account"

    return render(
        'migrate.html',
        auth=auth,
        user_id=user_id,
        handle=handle,
        platform=platform,
    )


#
# OAuth
#
class MastodonStart(FlashErrors, oauth_dropins.mastodon.Start):
    pass

class MastodonCallback(FlashErrors, oauth_dropins.mastodon.Callback):
    pass

class PixelfedStart(FlashErrors, oauth_dropins.pixelfed.Start):
    pass

class PixelfedCallback(FlashErrors, oauth_dropins.pixelfed.Callback):
    pass

class ThreadsStart(FlashErrors, oauth_dropins.threads.Start):
    pass

class ThreadsCallback(FlashErrors, oauth_dropins.threads.Callback):
    pass


app.add_url_rule('/oauth/mastodon/start', view_func=MastodonStart.as_view(
                     '/oauth/mastodon/start', '/oauth/mastodon/finish'),
                 methods=['POST'])
app.add_url_rule('/oauth/mastodon/finish', view_func=MastodonCallback.as_view(
                     '/oauth/mastodon/finish', '/review'))

app.add_url_rule('/oauth/pixelfed/start', view_func=PixelfedStart.as_view(
                     '/oauth/pixelfed/start', '/oauth/pixelfed/finish'),
                 methods=['POST'])
app.add_url_rule('/oauth/pixelfed/finish', view_func=PixelfedCallback.as_view(
                     '/oauth/pixelfed/finish', '/review'))

app.add_url_rule('/oauth/threads/start', view_func=ThreadsStart.as_view(
                     '/oauth/threads/start', '/oauth/threads/finish'),
                 methods=['POST'])
app.add_url_rule('/oauth/threads/finish', view_func=ThreadsCallback.as_view(
                     '/oauth/threads/finish', '/review'))


#
# Bluesky OAuth
#
def bluesky_oauth_client_metadata():
    return {
        **oauth_dropins.bluesky.CLIENT_METADATA_TEMPLATE,
        'client_id': f'{request.host_url}oauth/bluesky/client-metadata.json',
        'client_name': 'Bounce',
        'client_uri': request.host_url,
        'redirect_uris': [f'{request.host_url}oauth/bluesky/finish'],
    }

class BlueskyOAuthStart(FlashErrors, oauth_dropins.bluesky.OAuthStart):
    @property
    def CLIENT_METADATA(self):
        return bluesky_oauth_client_metadata()

class BlueskyOAuthCallback(FlashErrors, oauth_dropins.bluesky.OAuthCallback):
    @property
    def CLIENT_METADATA(self):
        return bluesky_oauth_client_metadata()


@app.get('/oauth/bluesky/client-metadata.json')
@flask_util.headers(CACHE_CONTROL)
def bluesky_oauth_client_metadata_handler():
    """https://docs.bsky.app/docs/advanced-guides/oauth-client#client-and-server-metadata"""
    return bluesky_oauth_client_metadata()


app.add_url_rule('/oauth/bluesky/start', view_func=BlueskyOAuthStart.as_view(
    '/oauth/bluesky/start', '/oauth/bluesky/finish'), methods=['POST'])
app.add_url_rule('/oauth/bluesky/finish', view_func=BlueskyOAuthCallback.as_view(
    '/oauth/bluesky/finish', '/review'))
