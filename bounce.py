"""UI pages."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from itertools import chain
import json
import logging
from pathlib import Path
import sys

from flask import flash, Flask, redirect, render_template, request
import flask_gae_static
from google.cloud import ndb
from granary import as2
from granary.bluesky import Bluesky
from granary.mastodon import Mastodon
from granary.pixelfed import Pixelfed
import oauth_dropins
import oauth_dropins.bluesky
import oauth_dropins.indieauth
import oauth_dropins.mastodon
import oauth_dropins.pixelfed
import oauth_dropins.threads
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
    util,
)
from oauth_dropins.webutil.flask_util import error, FlashErrors, get_required_param
from requests import RequestException
from requests_oauth2client import DPoPTokenSerializer, OAuth2AccessTokenAuth

# from Bridgy Fed
from activitypub import ActivityPub
from atproto import ATProto
import common
import models
from protocol import Protocol
from web import Web

logger = logging.getLogger(__name__)

PROTOCOLS = set(p for p in models.PROTOCOLS.values() if p and p.LABEL != 'ui')

BRIDGY_FED_PROJECT_ID = 'bridgy-federated'
bridgy_fed_ndb = ndb.Client(project=BRIDGY_FED_PROJECT_ID)

# Cache-Control header for static files
CACHE_CONTROL = {'Cache-Control': 'public, max-age=3600'}  # 1 hour

AUTH_TO_PROTOCOL = {
    oauth_dropins.bluesky.BlueskyAuth: ATProto,
    oauth_dropins.indieauth.IndieAuth: Web,
    oauth_dropins.mastodon.MastodonAuth: ActivityPub,
    oauth_dropins.pixelfed.PixelfedAuth: ActivityPub,
    oauth_dropins.threads.ThreadsAuth: ActivityPub,
}
BRIDGE_DOMAIN_TO_PROTOCOL = {
    'atproto.brid.gy': ATProto,
    'bsky.brid.gy': ATProto,
    'ap.brid.gy': ActivityPub,
    'fed.brid.gy': Web,
    'web.brid.gy': Web,
}


#
# Flask app
#
app = Flask(__name__, static_folder=None)
app.template_folder = './templates'
app.json.compact = False
app.config.from_pyfile(Path(__file__).parent / 'config.py')
app.url_map.converters['regex'] = flask_util.RegexConverter
app.after_request(flask_util.default_modern_headers)
app.register_error_handler(Exception, flask_util.handle_exception)

if appengine_info.LOCAL_SERVER:
    flask_gae_static.init_app(app)

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)

models.reset_protocol_properties()


#
# models
#
class Cache(ndb.Model):
    """Simple, dumb, datastore-backed key/value cache."""
    value = ndb.BlobProperty()
    expire = ndb.DateTimeProperty(tzinfo=timezone.utc)

    @classmethod
    def get(cls, key):
        """
        Args:
          key (str)

        Returns:
          str or None: value
        """
        if got := cls.get_by_id(key):
            if not got.expire or datetime.now(timezone.utc) < got.expire:
                return got.value.decode()

    @classmethod
    def put(cls, key, value, expire=None):
        """
        Args:
          key (str)
          value (str)
          expire (datetime.timedelta)
        """
        cached = cls(id=key, value=value.encode(),
                     expire=datetime.now(timezone.utc) + expire)
        super(cls, cached).put()


class Migration(ndb.Model):
    """Stores state for a migration.

    Key id is the from account's auth entity's key id.
    """
    to = ndb.KeyProperty()  # auth entity
    state = ndb.StringProperty(choices=('follows', 'out', 'in', 'done'),
                               default='follows')

    # user ids to follow
    to_follow = ndb.StringProperty(repeated=True)
    followed = ndb.StringProperty(repeated=True)

    last_attempt = ndb.DateTimeProperty(tzinfo=timezone.utc)
    created = ndb.DateTimeProperty(auto_now_add=True, tzinfo=timezone.utc)
    updated = ndb.DateTimeProperty(auto_now=True, tzinfo=timezone.utc)


#
# views
#
def render(template, login_forms=False, **vars):
    """Wrapper for Flask.render_template that populates common template vars.

    Args:
      login_forms (bool): whether to render and include the ``*_button`` variables
        with the OAuth login forms.
    """
    if 'auths' not in vars:
        vars['auths'] = [a for a in ndb.get_multi(oauth_dropins.get_logins()) if a]

    if login_forms:
        vars.update({
            'bluesky_button': oauth_dropins.bluesky.Start.button_html(
                '/oauth/bluesky/start', image_prefix='/oauth_dropins_static/'),
            'mastodon_button': oauth_dropins.mastodon.Start.button_html(
                '/oauth/mastodon/start', image_prefix='/oauth_dropins_static/'),
            'pixelfed_button': oauth_dropins.pixelfed.Start.button_html(
                '/oauth/pixelfed/start', image_prefix='/oauth_dropins_static/'),
            # threads_button': oauth_dropins.threads.Start.button_html(
            #     '/oauth/threads/start', image_prefix='/oauth_dropins_static/'),
        })

    return render_template(template, **vars)


def require_login(param):
    """Decorator that requires and loads a logged in user.

    Passes the user into a positional arg to the function, as an oauth-dropins auth
    entity.

    Args:
      param (str): HTTP query param with the url-safe ndb key for the oauth-dropins
        auth entity
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = ndb.Key(urlsafe=get_required_param(param))
            if key in oauth_dropins.get_logins():
                if auth := key.get():
                    return fn(*args, auth, **kwargs)

            logger.warning(f'not logged in for {key}')
            return redirect('/', code=302)

        return wrapper

    return decorator


def granary_source(auth):
    """Returns a granary source instance for a given auth entity.

    Args:
      auth (oauth_dropins.models.BaseAuth)

    Returns:
      granary.source.Source:
    """
    if isinstance(auth, (oauth_dropins.mastodon.MastodonAuth,
                         oauth_dropins.pixelfed.PixelfedAuth)):
        return Mastodon(instance=auth.instance(), access_token=auth.access_token_str,
                        user_id=auth.user_id())

    elif isinstance(auth, oauth_dropins.bluesky.BlueskyAuth):
        oauth_client = oauth_dropins.bluesky.oauth_client_for_pds(
            bluesky_oauth_client_metadata(), auth.pds_url)
        token = DPoPTokenSerializer.default_loader(auth.dpop_token)
        dpop_auth = OAuth2AccessTokenAuth(client=oauth_client, token=token)
        return Bluesky(pds_url=auth.pds_url, handle=auth.user_display_name(),
                       did=auth.key.id(), auth=dpop_auth)


def get_user(auth):
    """Loads and returns the Bridgy Fed user for a given auth entity.

    Args:
      auth (oauth_dropins.models.BaseAuth)

    Returns:
      models.User:
    """
    with ndb.context.Context(bridgy_fed_ndb).use():
        if isinstance(auth, (oauth_dropins.mastodon.MastodonAuth,
                             oauth_dropins.pixelfed.PixelfedAuth)):
            return ActivityPub.get_or_create(json.loads(auth.user_json)['uri'])
        elif isinstance(auth, oauth_dropins.bluesky.BlueskyAuth):
            return ATProto.get_or_create(auth.key.id())


@app.get('/')
@flask_util.headers(CACHE_CONTROL)
def front_page():
    """View for the front page."""
    return render('index.html', login_forms=True)

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
    logins = oauth_dropins.get_logins()
    if not logins:
        return redirect('/', code=302)

    auths = []
    for auth in ndb.get_multi(logins):
        if auth:
            auth.url = f'/review?key={auth.key.urlsafe().decode()}'
            auths.append(auth)

    return render('accounts.html', auths=auths)


@app.get('/review')
@require_login('auth')
def review(auth):
    """Review an account's followers and follows."""
    cache_key = f'review-html-{auth.key.id()}'
    if 'force' not in request.args:
        if cached := Cache.get(cache_key):
            logger.info(f'Returning cached review for {auth.key.id()}')
            return cached

    logger.info(f'Reviewing {auth.key.id()} {auth.user_display_name()}')

    source = granary_source(auth)
    auth.url = source.to_as1_actor(json.loads(auth.user_json)).get('url')
    from_proto = AUTH_TO_PROTOCOL[auth.__class__]
    assert from_proto in (ActivityPub, ATProto)

    # TODO: user chooses account they're migrating to first!
    to_proto = ATProto if from_proto == ActivityPub else ActivityPub
    assert to_proto in (ActivityPub, ATProto)

    #
    # followers
    #
    logger.info('Fetching followers')
    followers = source.get_followers()
    ids = [f['id'] for f in followers if f.get('id')]
    for follower in followers:
        follower['image'] = util.get_first(follower, 'image')

    if from_proto.HAS_COPIES:
        follower_counts = []
        with ndb.context.Context(bridgy_fed_ndb).use():
            for proto in PROTOCOLS:
                if proto != from_proto:
                    count = proto.query(proto.copies.uri.IN(ids)).count()
                    follower_counts.append([proto.__name__, count])
        rest = sum(count for _, count in follower_counts)
        follower_counts.append([from_proto.__name__, len(followers) - rest])

    else:
        by_protocol = defaultdict(list)
        for id in ids:
            domain = util.domain_from_link(id)
            by_protocol[BRIDGE_DOMAIN_TO_PROTOCOL.get(domain, ActivityPub)].append(id)
        follower_counts = list((model.__name__, len(ids)) for model, ids in by_protocol.items())

    logger.info(f'  {len(followers)} total, {follower_counts}')

    #
    # follows
    #
    logger.info('Fetching follows')
    follows = source.get_follows()

    ids_by_proto = defaultdict(list)
    for followee in follows:
        followee['image'] = util.get_first(followee, 'image')
        # STATE TODO: if wrapped, extract from protocol
        id = common.unwrap(followee.get('id'))
        proto = Protocol.for_id(id, remote=False) or from_proto
        ids_by_proto[proto].append(id)

    follow_counts = []
    with ndb.context.Context(bridgy_fed_ndb).use():
        if from_proto.HAS_COPIES:
            ids = list(chain(*ids_by_proto.values()))
            for proto in PROTOCOLS:
                if proto == from_proto:
                    query = proto.query(proto.key.IN([proto(id=id).key for id in ids]))
                else:
                    query = proto.query(proto.copies.uri.IN(ids))
                if proto != to_proto:
                    query = query.filter(proto.enabled_protocols == to_proto.LABEL)
                follow_counts.append([f'{proto.__name__}', query.count()])

        else:
            for proto, ids in ids_by_proto.items():
                if proto == to_proto:
                    bridged = len(ids)
                else:
                    bridged = proto.query(
                        proto.key.IN([proto(id=id).key for id in ids]),
                        proto.enabled_protocols == to_proto.LABEL,
                    ).count()

                follow_counts.append([f'{proto.__name__}', bridged])

    total_bridged = sum(count for _, count in follow_counts)
    follow_counts.append(['not bridged', len(follows) - total_bridged])

    logger.info(f'  {len(follows)} total, {follow_counts}')

    # preprocess actors
    if from_proto == ActivityPub:
        for f in followers + follows:
            f['username'] = as2.address(as2.from_as1(f))

    html = render(
        'review.html',
        auth=auth,
        to_proto=to_proto,
        followers=followers,
        follows=follows,
        follower_counts=[['type', 'count']] + sorted(follower_counts),
        follow_counts=[['type', 'count']] + sorted(follow_counts),
        keep_follows_pct=round(total_bridged / len(follows) * 100),
    )
    Cache.put(cache_key, html, expire=timedelta(days=30))
    return html


@app.get('/choose-to-account')
@require_login('from_auth')
def choose_to_account(from_auth):
    logins = oauth_dropins.get_logins()
    if not logins:
        return redirect('/', code=302)

    auths = []
    for auth in ndb.get_multi(logins):
        if auth:
            auth.url = f'/migrate-confirm?from_auth={from_auth.key.urlsafe().decode()}&to_auth={auth.key.urlsafe().decode()}'
            auths.append(auth)

    return render('choose_to_account.html', login_forms=True, auths=auths)

@app.get('/migrate')
@require_login('from_auth')
@require_login('to_auth')
def migrate_confirm(from_auth, to_auth):
    """View for the migration confirmation page."""
    return render(
        'migrate.html',
    )

@app.post('/migrate')
@require_login('from_auth')
@require_login('to_auth')
def migrate(from_auth, to_auth):
    """Migration handler."""
    logger.info(f'Migrating {from_auth.key.id()}')

    if not (migration := Migration.get_by_id(from_auth.key.id())):
        error('migration not found', status=404)

    migration.last_attempt = util.now()
    migration.put()

    from_user = get_user(from_auth)
    to_user = get_user(to_auth)
    assert from_user.__class__ != to_user.__class__

    if migration.state == 'follows':
        migrate_follows(migration, to_auth)
        migration.state = 'out'
        migration.put()

    if migration.state == 'out':
        migrate_out(migration, from_user, to_user)
        migration.state = 'in'
        migration.put()

    if migration.state == 'in':
        migrate_in(migration, from_user, to_user)
        migration.state = 'done'
        migration.put()

    # TODO: final report
    return 'ok'


def migrate_follows(migration, to_auth):
    """Creates follows in the destination account.

    Args:
      migration (Migration)
      to_auth (oauth_dropins.models.BaseAuth)
    """
    logging.info(f'Creating follows for {to_auth.key_id()}')
    to_follow = migration.to_follow
    migration.to_follow = []
    source = granary_source(to_auth)

    for user_id in to_follow:
        logger.info(f'Folowing {user_id}')
        try:
            # Use the granary source to create the follow
            result = source.create({
                'objectType': 'activity',
                'verb': 'follow',
                'object': user_id,
            })
            if result.error_plain:
                logger.warning(f'Failed: {result.error_plain}')
                migration.to_follow.append(user_id)
                continue

            migration.followed.append(user_id)

        except BaseException as e:
            logger.warning(f'Failed: {e}')
            migration.to_follow.append(user_id)
            code, _ = util.interpret_http_exception(e)
            if not code:
                migration.put()
                raise


def migrate_out(migration, from_user, to_user):
    """Migrates a Bridgy Fed bridged account out to a native account.

    Args:
      migration (Migration)
      from_user (models.User)
      to_user (models.User)
    """
    logging.info(f'Migrating bridged account {from_user.key.id()} out to {to_user.key.id()}')
    # to_user.migrate_out(from_user, to_user.key.id())


def migrate_in(migration, from_user, to_user):
    """Migrates a source native account into Bridgy Fed to be a bridged account.

    Args:
      migration (Migration)
      from_user (models.User)
      to_user (models.User)
    """
    logging.info(f'Migrating {from_user.key.id()} in to bridged account TODO')
    # from_user.migrate_out(to_user, from_user.key.id(),
    #                       # TODO
    #                       plc_code, dpop_token)


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

# class ThreadsStart(FlashErrors, oauth_dropins.threads.Start):
#     pass

# class ThreadsCallback(FlashErrors, oauth_dropins.threads.Callback):
#     pass


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

# app.add_url_rule('/oauth/threads/start', view_func=ThreadsStart.as_view(
#                      '/oauth/threads/start', '/oauth/threads/finish'),
#                  methods=['POST'])
# app.add_url_rule('/oauth/threads/finish', view_func=ThreadsCallback.as_view(
#                      '/oauth/threads/finish', '/review'))


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
