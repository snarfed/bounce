"""UI pages."""
import logging
from functools import wraps

from flask import flash, redirect, render_template, request
from google.cloud import ndb
from granary.bluesky import Bluesky
from granary.mastodon import Mastodon
import oauth_dropins
import oauth_dropins.bluesky
import oauth_dropins.mastodon
import oauth_dropins.pixelfed
import oauth_dropins.threads
from oauth_dropins.webutil import flask_util
from oauth_dropins.webutil.flask_util import FlashErrors

from flask_app import app

logger = logging.getLogger(__name__)

# Cache-Control header for static files
CACHE_CONTROL = {'Cache-Control': 'public, max-age=3600'}  # 1 hour


def require_login(fn):
    """Decorator that requires and loads the current request's logged in user.

    Passes the user in the ``user`` kwarg, as a :class:`models.User`.

    HTTP params:
      key (str): url-safe ndb key for an oauth-dropins auth entity
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = Key(urlsafe=get_required_param('key'))
        if key not in oauth_dropins.get_logins():
            logger.warning(f'not logged in for {key}')
            raise Found(location='/')

        return fn(*args, user=user, **kwargs)

    return wrapper


@app.get('/')
@flask_util.headers(CACHE_CONTROL)
def front_page():
    """View for the front page."""
    return render_template('index.html',
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
    return render_template('docs.html')


@app.post('/logout')
def logout():
    """Logs the user out of all current login sessions."""
    flask_util.logout()
    flash("OK, you're now logged out.")
    return redirect('/', code=302)


@app.get('/accounts')
def accounts():
    """User accounts page. Requires logged in session."""
    if not (logins := oauth_dropins.get_logins()):
        return redirect('/', code=302)

    auths = ndb.get_multi(logins)
    return render_template(
        'accounts.html',
        auths=auths,
    )


@app.get('/review')
@require_login
def review():
    """Review an account's followers and follows."""
    # Determine which service the user is logged in with
    auth = g.auth

    # Get followers and follows based on the service
    followers = []
    follows = []
    if auth.__class__ == bluesky.Auth:
        # Get Bluesky followers and follows
        api = Bluesky(auth_entity=auth)
        followers = api.get_followers()
        follows = api.get_follows()
    elif auth.__class__ in (mastodon.Auth, pixelfed.Auth):
        # Get Mastodon/Pixelfed followers and follows
        api = Mastodon(auth_entity=auth)
        followers = api.get_followers()
        follows = api.get_follows()
    elif auth.__class__ == threads.Auth:
        # For Threads, we'd use a similar approach
        # But we can't yet since Threads API is limited
        pass

    # Get user info
    user_id = None
    handle = None
    if hasattr(auth, 'user_json') and auth.user_json:
        if auth.__class__ == bluesky.Auth:
            user_id = auth.user_json.get('did')
            handle = auth.user_json.get('handle')
        elif auth.__class__ in (mastodon.Auth, pixelfed.Auth, threads.Auth):
            user_id = str(auth.user_json.get('id'))
            handle = auth.user_json.get('username')

    return render_template(
        'review.html',
        auth=auth,
        user_id=user_id,
        handle=handle,
        followers=followers,
        follows=follows,
    )


@app.get('/migrate')
@require_login
def migrate():
    """View for the migration preparation page."""
    # Get user info
    auth = g.auth
    user_id = None
    handle = None
    platform = "account"

    return render_template(
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
