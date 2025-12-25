"""UI pages."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import auto, IntEnum
from functools import wraps
from itertools import chain
import json
import logging
import os
from pathlib import Path
import sys
from urllib.parse import urljoin

from arroba import xrpc_repo
from arroba.datastore_storage import AtpRemoteBlob, DatastoreStorage
import arroba.server
from flask import Flask, redirect, render_template, request
import flask_gae_static
from google.cloud import ndb, storage
from google.cloud.ndb.key import Key
from granary import as2
from granary.bluesky import Bluesky
from granary.mastodon import Mastodon
from granary.pixelfed import Pixelfed
import humanize
import lexrpc
import oauth_dropins
import oauth_dropins.bluesky
from oauth_dropins.bluesky import BlueskyAuth
from oauth_dropins.indieauth import IndieAuth
import oauth_dropins.mastodon
from oauth_dropins.mastodon import MastodonAuth
import oauth_dropins.pixelfed
from oauth_dropins.pixelfed import PixelfedAuth
import oauth_dropins.threads
from oauth_dropins.threads import ThreadsAuth
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
    util,
)
from oauth_dropins.webutil.flask_util import (
    canonicalize_domain,
    cloud_tasks_only,
    error,
    flash,
    FlashErrors,
    Found,
    get_required_param,
)
from oauth_dropins.webutil.models import EnumProperty, JsonProperty
from oauth_dropins.webutil.util import json_dumps, json_loads
from pymemcache.test.utils import MockMemcacheClient
import pytz
from requests import RequestException
from requests_oauth2client import TokenSerializer, OAuth2AccessTokenAuth

# from Bridgy Fed
from activitypub import ActivityPub
from atproto import ATProto
import common
import ids
from ids import translate_user_id
import memcache
import models
from protocol import Protocol
from web import Web

logger = logging.getLogger(__name__)

PROTOCOLS = set(p for p in models.PROTOCOLS.values() if p and p.LABEL != 'ui')

BRIDGY_FED_PROJECT_ID = 'bridgy-federated'
bridgy_fed_ndb = ndb.Client(project=BRIDGY_FED_PROJECT_ID)
# haven't yet managed to get Bounce to access Bridgy Fed's memcache. See section
# at end of README.md. To test, remove memcache.memcache.client_class here.
memcache.memcache.client_class = memcache.pickle_memcache.client_class = MockMemcacheClient

# Cache-Control header for static files
CACHE_CONTROL = {'Cache-Control': 'public, max-age=3600'}  # 1 hour

TASK_REQUESTS_KWARGS = {
    'timeout': 60,  # seconds
}

FOLLOWERS_PREVIEW_LEN = 20

AUTH_TO_PROTOCOL = {
    BlueskyAuth: ATProto,
    IndieAuth: Web,
    MastodonAuth: ActivityPub,
    PixelfedAuth: ActivityPub,
    ThreadsAuth: ActivityPub,
}
BRIDGE_DOMAIN_TO_PROTOCOL = {
    'atproto.brid.gy': ATProto,
    'bsky.brid.gy': ATProto,
    'ap.brid.gy': ActivityPub,
    'fed.brid.gy': Web,
    'web.brid.gy': Web,
}
SETTINGS_PATH_ALIAS = {
    MastodonAuth: '/settings/aliases',
    PixelfedAuth: '/settings/account/aliases/manage',
}
SETTINGS_PATH_MIGRATE = {
    MastodonAuth: '/settings/migration',
    PixelfedAuth: '/settings/account/migration/manage',
}
DOCS_URL_MIGRATE = {
    MastodonAuth: 'https://docs.joinmastodon.org/user/moving/#migration',
    PixelfedAuth: '/site/kb/your-profile#migration',
}

# if a Migration hasn't been touched in this long, we'll restart its review or
# migrate task on the next user request
STALE_TASK_AGE = timedelta(minutes=5)

MAIN_PDS_DOMAINS = ('bsky.app', 'bsky.network', 'bsky.social')

CLOUD_STORAGE_BUCKET = 'bridgy-federated.appspot.com'
CLOUD_STORAGE_BASE_URL = 'https://storage.googleapis.com/'

USER_AGENT = 'Bounce (https://bounce.anew.social/)'
util.set_user_agent(USER_AGENT)

DOMAIN = 'bounce.anew.social'
APPSPOT_DOMAIN = 'bounce-migrate.appspot.com'


#
# Flask app
#
app = Flask(__name__, static_folder=None)
app.template_folder = './templates'
app.json.compact = False
app.config.from_pyfile(Path(__file__).parent / 'config.py')
app.url_map.converters['regex'] = flask_util.RegexConverter
app.before_request(canonicalize_domain([APPSPOT_DOMAIN], DOMAIN))
app.after_request(flask_util.default_modern_headers)
app.register_error_handler(Exception, flask_util.handle_exception)

if appengine_info.LOCAL_SERVER:
    flask_gae_static.init_app(app)

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)

models.reset_protocol_properties()

arroba.server.storage = DatastoreStorage(ndb_client=bridgy_fed_ndb)


#
# models
#
class State(IntEnum):
    # in order!
    review_followers = auto()
    review_follows = auto()
    review_analyze = auto()
    review_done = auto()
    migrate_follows = auto()
    migrate_in = auto()
    migrate_in_blobs = auto()
    migrate_out = auto()
    migrate_done = auto()


class Migration(ndb.Model):
    """Stores state for a migration.

    Key id is '[from auth entity id] [to protocol Bridgy Fed label]', eg
    'did:plc:alice activitypub'.
    """
    from_ = ndb.KeyProperty()  # auth entities
    to = ndb.KeyProperty()

    state = EnumProperty(State)

    # data for review. contents depend on state. if state is review_done, these
    # are template parameters for rendering review.html.
    review = JsonProperty(default={})

    # user ids to follow
    to_follow = ndb.StringProperty(repeated=True)
    followed = ndb.StringProperty(repeated=True)

    # required for migrating from Bluesky; unused for others
    plc_code = ndb.StringProperty()

    last_attempt = ndb.DateTimeProperty(tzinfo=timezone.utc)
    created = ndb.DateTimeProperty(auto_now_add=True, tzinfo=timezone.utc)
    updated = ndb.DateTimeProperty(auto_now=True, tzinfo=timezone.utc)

    @classmethod
    def _key_id(cls, from_auth, to_auth):
        return f'{from_auth.key.id()} {AUTH_TO_PROTOCOL[to_auth.__class__].LABEL}'

    @classmethod
    def get(cls, from_auth, to_auth):
        """
        Args:
          from_auth (oauth_dropins.models.BaseAuth)
          to_auth (oauth_dropins.models.BaseAuth)

        Returns:
          Migration:
        """
        id = cls._key_id(from_auth, to_auth)
        logger.info(f'get Migration {id}')
        return cls.get_by_id(id)

    @classmethod
    @ndb.transactional()
    def get_or_insert(cls, from_auth, to_auth, **kwargs):
        """
        Args:
          from_auth (oauth_dropins.models.BaseAuth)
          to_auth (oauth_dropins.models.BaseAuth)
          kwargs: passed to :meth:`ndb.Model.get_or_insert`

        Returns:
          Migration:
        """
        id = cls._key_id(from_auth, to_auth)
        logger.info(f'get_or_insert Migration {id} {kwargs}')

        if not (migration := cls.get_by_id(id)):
            migration = Migration(id=id, from_=from_auth.key, to=to_auth.key, **kwargs)
            migration.put()

        return migration

    def create_task(self, queue):
        """Creates a review or migrate task for this migration.

        Args:
          queue: 'review' or 'migrate'
        """
        assert queue in ('review', 'migrate'), queue
        common.create_task(queue, app_id=appengine_info.APP_ID, app=app, **{
            'from': self.from_.urlsafe().decode(),
            'to': self.to.urlsafe().decode(),
        })


def humanize_number(num, noun):
    """Generates a string for a number of objects in a human-friendly form.

    Eg ``12k widgets``, ``2M fluffs``, ``1 foo``.

    Args:
      num (int)
      noun (str)

    Returns:
      str:
    """
    # hacky, uses humanize's file size function and then tweaks it
    # https://humanize.readthedocs.io/en/latest/filesize/
    number = humanize.naturalsize(num, format='%.0f')\
                     .upper().removesuffix('BYTES').removesuffix('BYTE')\
                     .rstrip('B').replace(' ', '')
    if num != 1:
        noun += 's'

    return f'{number} {noun}'



def url(path, from_auth, to_auth=None):
    """Simple helper to create URLs with from and optional to auth entities.

    Args:
          from_auth (oauth_dropins.models.BaseAuth)
          to_auth (oauth_dropins.models.BaseAuth)

    Returns:
      str: URL with ``from`` and optionally ``to`` query params
    """
    url = f'{path}?from={from_auth.key.urlsafe().decode()}'
    if to_auth:
        url += f'&to={to_auth.key.urlsafe().decode()}'

    return url


def template_vars():
    """Returns base template vars common to most views."""
    auths = []
    for auth in ndb.get_multi(oauth_dropins.get_logins()):
        if auth:
            user_json = json.loads(auth.user_json)
            if not (source := granary_source(auth)):
                continue
            auth.url = source.to_as1_actor(user_json).get('url')
            auths.append(auth)

    return {
        'auths': auths,
        'humanize_number': humanize_number,
        'request': request,
        'util': util,
    }


def require_accounts(from_params, to_params=None, logged_in=True, failures_to=None):
    """Decorator that requires and loads both from and (optionally) to auth entities.

    Passes both entities as positional args to the function, as oauth-dropins auth
    entities. Also performs sanity checks:
    * Both must be logged in (if ``logged_in`` is True)
    * They must be different protocols
    * If a Bluesky account is involved, it can't be a did:web

    Args:
      from_params (str or sequence of str): HTTP query param(s) with the url-safe ndb
        key for the from auth entity
      to_params (str or sequence of str): HTTP query param(s) with the url-safe ndb key
        for the to auth entity
      logged_in (bool): whether to require the auth entities are actually logged in
      failures_to (str): optional URL path to redirect to if the user declines or
        an error happens.
    """
    assert from_params
    if isinstance(from_params, str):
        from_params = [from_params]
    if isinstance(to_params, str):
        to_params = [to_params]

    def load(params):
        for param in params:
            if urlsafe_key := request.values.get(param):
                break
        else:
            error(f'missing one of required params: {params}')

        key = ndb.Key(urlsafe=urlsafe_key)
        if auth := key.get():
            if not logged_in or key in oauth_dropins.get_logins():
                return auth

        logger.warning(f'not logged in for {key}')
        raise Found(location='/')

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if request.values.get('declined'):
                flash("You'll need to approve the prompt to continue.")
                return redirect(failures_to or '/')

            from_auth = load(from_params)
            args += (from_auth,)

            to_auth = None
            if to_params:
                to_auth = load(to_params)
                if (AUTH_TO_PROTOCOL[from_auth.__class__]
                        == AUTH_TO_PROTOCOL[to_auth.__class__]):
                    error(f"Can't migrate {from_auth.__class__.__name__} to {to_auth.__class__.__name__}")
                args += (to_auth,)

            # Check for did:web in Bluesky accounts
            for auth in (from_auth, to_auth):
                if (isinstance(auth, BlueskyAuth)
                        and auth.key.id().startswith('did:web:')):
                    flash('Sorry, did:webs are not currently supported.')
                    return redirect('/')

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def bluesky_session_callback(auth_entity):
    """Returns a callable to pass to lexrpc.Client as session_callback.

    When an access token or OAuth DPoP token is refreshed, stores the new token
    back to the datastore in the auth entity.
    """
    def callback(session_or_auth):
        if isinstance(session_or_auth, dict):
            if session_or_auth != auth_entity.session:
                auth_entity.session = session_or_auth
                auth_entity.put()

        elif isinstance(session_or_auth, OAuth2AccessTokenAuth):
            serialized = TokenSerializer().dumps(auth.dpop_token)
            if session_or_auth.token != serialized:
                auth_entity.dpop_token = serialized
                auth_entity.put()


def granary_source(auth, with_auth=False, **requests_kwargs):
    """Returns a granary source instance for a given auth entity.

    Args:
      auth (oauth_dropins.models.BaseAuth)
      with_auth (bool)
      requests_kwargs (dict): passed to :func:`requests.get`/:func:`requests.post`

    Returns:
      granary.source.Source:
    """
    if isinstance(auth, (MastodonAuth, PixelfedAuth)):
        try:
            instance = instance=auth.instance()
        except RuntimeError as e:
            # the MastodonApp entity probably got deleted manually. oauth-dropins
            # will have cleaned this up and logged out the bad login.
            return None

        cls = {
            MastodonAuth: Mastodon,
            PixelfedAuth: Pixelfed,
        }[auth.__class__]
        return cls(instance, access_token=auth.access_token_str,
                   user_id=auth.user_id(), **requests_kwargs)

    elif isinstance(auth, BlueskyAuth):
        if with_auth:
            oauth_client = oauth_dropins.bluesky.oauth_client_for_pds(
                bluesky_oauth_client_metadata(), auth.pds_url)
            token = TokenSerializer().loads(auth.dpop_token)
            dpop_auth = OAuth2AccessTokenAuth(client=oauth_client, token=token)
            requests_kwargs['auth'] = dpop_auth

        return Bluesky(pds_url=auth.pds_url, handle=auth.user_display_name(),
                       did=auth.key.id(), session_callback=bluesky_session_callback,
                       **requests_kwargs)


def _get_user(auth):
    """Loads and returns the Bridgy Fed user for a given auth entity.

    Args:
      auth (oauth_dropins.models.BaseAuth)

    Returns:
      models.User:
    """
    proto = AUTH_TO_PROTOCOL[auth.__class__]
    id = auth.actor_id() if proto == ActivityPub else auth.key.id()

    with ndb.context.Context(bridgy_fed_ndb).use():
        return proto.get_or_create(id, allow_opt_out=True)

get_to_user = get_from_user = _get_user


#
# views
#
@app.get('/')
@flask_util.headers(CACHE_CONTROL)
def front_page():
    """View for the front page."""
    return render_template('index.html', **template_vars())


@app.get('/docs')
@flask_util.headers(CACHE_CONTROL)
def docs():
    """View for the docs page."""
    return render_template('docs.html', **template_vars())


@app.post('/logout')
def logout():
    """Logs the user out of all current login sessions."""
    oauth_dropins.logout()
    flash("OK, you're now logged out.")
    return redirect('/')


@app.get('/from')
def choose_from():
    """Choose account to migrate from."""
    vars = template_vars()

    accounts = vars['auths']
    for acct in accounts:
        acct.url = url('/to', acct)

    return render_template(
        'accounts.html',
        body_id='from',
        accounts=accounts,
        bluesky_button=oauth_dropins.bluesky.Start.button_html(
            '/oauth/bluesky/start/from',
            image_prefix='/oauth_dropins_static/'),
        mastodon_button=oauth_dropins.mastodon.Start.button_html(
            '/oauth/mastodon/start/from',
            image_prefix='/oauth_dropins_static/'),
        # https://github.com/snarfed/bounce/issues/53
        # pixelfed_button=oauth_dropins.pixelfed.Start.button_html(
        #     '/oauth/pixelfed/start/from',
        #     image_prefix='/oauth_dropins_static/'),
        # https://github.com/snarfed/bounce/issues/57
        # threads_button=oauth_dropins.threads.Start.button_html(
        #     '/oauth/threads/start/from',
        #     image_prefix='/oauth_dropins_static/'),
        **vars,
    )


@app.get('/to')
@require_accounts(('from', 'auth_entity'), failures_to='/from')
def choose_to(from_auth):
    """Choose account to migrate to."""
    if from_auth.key.id().startswith('did:web:'):
        flash('Sorry, did:webs are not currently supported.')
        return redirect('/')

    vars = template_vars()

    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    accounts = [auth for auth in vars['auths']
                if from_proto != AUTH_TO_PROTOCOL[auth.__class__]]
    for acct in accounts:
        acct.url = url('/review', from_auth, acct)

    state = f'<input type="hidden" name="state" value="{from_auth.key.urlsafe().decode()}" />'
    if from_proto != ATProto:
        vars['bluesky_button'] = oauth_dropins.bluesky.Start.button_html(
            '/oauth/bluesky/start/to',
            image_prefix='/oauth_dropins_static/', form_extra=state)
    if from_proto != ActivityPub:
        vars.update({
            'mastodon_button': oauth_dropins.mastodon.Start.button_html(
                '/oauth/mastodon/start/to',
                image_prefix='/oauth_dropins_static/', form_extra=state),
            'pixelfed_button': oauth_dropins.pixelfed.Start.button_html(
                '/oauth/pixelfed/start/to',
                image_prefix='/oauth_dropins_static/', form_extra=state),
            # https://github.com/snarfed/bounce/issues/57
            # 'threads_button': oauth_dropins.threads.Start.button_html(
            #     '/oauth/threads/start/to',
            #     image_prefix='/oauth_dropins_static/', form_extra=state),
        })

    return render_template(
        'accounts.html',
        body_id='to',
        from_auth=from_auth,
        from_proto=from_proto,
        accounts=accounts,
        **vars,
    )


@app.get('/review')
@require_accounts(('from', 'state'), ('to', 'auth_entity'), failures_to='/from')
def review(from_auth, to_auth):
    """Reviews a "from" account's followers and follows."""
    force = 'force' in request.args

    migration = Migration.get_or_insert(from_auth, to_auth)

    if migration.state and migration.state >= State.migrate_follows:
        msg = f'{from_auth.user_display_name()} has already begun migrating to {migration.to.get().user_display_name()}.'
        if migration.to == to_auth.key:
            logger.info(msg)
            return redirect(url('/migrate', from_auth, to_auth))
        else:
            flash(msg)
            return redirect(url('/to', from_auth))

    # check that "to" user is eligible
    get_to_user(to_auth)

    if migration.to and migration.to != to_auth.key:
        logger.info(f'  overwriting existing to {migration.to} with {to_auth.key}')
        migration.to = to_auth.key

    if force:
        # restart from the beginning
        migration.state = State.review_followers
        migration.review = {}
        migration.followed = []
        migration.to_follow = []

    new_task = force or util.now() - migration.updated >= STALE_TASK_AGE
    if not migration.state:
        migration.state = State.review_followers
        new_task = True

    migration.put()

    if new_task:
        migration.create_task('review')

    if force:
        # don't meta refresh reload with the force query param, since that would
        # create a new task on every refresh
        path, _ = util.remove_query_param(request.full_path, 'force')
        return redirect(path)

    return render_template(
        ('review.html' if migration.state == State.review_done
         else 'review_progress.html'),
        from_auth=from_auth,
        to_auth=to_auth,
        migration=migration,
        State=State,
        **migration.review,
        **template_vars(),
    )


@app.post('/queue/review')
@cloud_tasks_only()
@require_accounts('from', 'to', logged_in=False)
def review_task(from_auth, to_auth):
    """Review a "from" account's followers and follows."""
    logger.info(f'Params: {list(request.values.items())}')
    logger.info(f'Reviewing {from_auth.key.id()} {from_auth.user_display_name()} => {to_auth.site_name()}')
    migration = Migration.get(from_auth, to_auth)
    assert migration, (from_auth, to_auth)

    logger.info(f'  {migration.key} {migration.state.name if migration.state else "new"}')
    if migration.state is None:
        migration.state = State.review_followers
    assert migration.state <= State.review_done

    source = granary_source(from_auth, with_auth=True, **TASK_REQUESTS_KWARGS)
    from_auth.url = source.to_as1_actor(json.loads(from_auth.user_json)).get('url')

    # Process based on migration state
    if migration.state == State.review_followers:
        logger.info('starting review_followers')
        review_followers(migration, from_auth)
        migration.state = State.review_follows
        migration.put()
        logger.info('finished, now at review_follows')

    if migration.state == State.review_follows:
        logger.info('starting review_follows')
        review_follows(migration, from_auth, to_auth)
        migration.state = State.review_analyze
        migration.put()
        logger.info('finished, now at review_analyze')

    if migration.state == State.review_analyze:
        logger.info('starting review_analyze')
        analyze_review(migration, from_auth)
        migration.state = State.review_done
        migration.put()
        logger.info('finished, now at review_done')

    return 'OK'


def review_followers(migration, from_auth):
    """Fetches followers for the account being reviewed.

    Args:
      migration (Migration)
      from_auth (oauth_dropins.models.BaseAuth)
    """
    logger.info(f'Fetching followers for {from_auth.key_id()}')
    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]

    source = granary_source(from_auth, with_auth=True, **TASK_REQUESTS_KWARGS)

    with ndb.context.Context(bridgy_fed_ndb).use():
        bot_user_ids = common.bot_user_ids()
    followers = [f for f in source.get_followers()
                 if f.get('id') and f['id'] not in bot_user_ids]

    if not followers:
        logger.info('no followers!')
        migration.review.update({
            'followers_preview_raw': [],
            'follower_counts': [],
        })
        return

    ids = [f['id'] for f in followers]

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
        by_proto = defaultdict(list)
        for id in ids:
            domain = util.domain_from_link(id)
            by_proto[BRIDGE_DOMAIN_TO_PROTOCOL.get(domain, ActivityPub)].append(id)
        follower_counts = list((model.__name__, len(ids))
                               for model, ids in by_proto.items())

    logger.info(f'  {len(followers)} total, {follower_counts}')

    migration.review.update({
        'followers_preview_raw': followers[:FOLLOWERS_PREVIEW_LEN],
        'follower_counts': follower_counts,
    })


def review_follows(migration, from_auth, to_auth):
    """Fetches follows for the account being reviewed.

    Args:
      migration (Migration)
      from_auth (oauth_dropins.models.BaseAuth)
      to_auth (oauth_dropins.models.BaseAuth)
    """
    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    to_proto = AUTH_TO_PROTOCOL[to_auth.__class__]
    logger.info(f'Fetching follows for {from_auth.key_id()} with to proto {to_proto.LABEL}')

    source = granary_source(from_auth, with_auth=True, **TASK_REQUESTS_KWARGS)

    with ndb.context.Context(bridgy_fed_ndb).use():
        bot_user_ids = common.bot_user_ids()
    follows = [f for f in source.get_follows() if f.get('id') not in bot_user_ids]

    if not follows:
        logger.info('no follows!')
        migration.review.update({
            'follows_preview_raw': [],
            'follow_counts': [],
            'total_bridged_follows': 0,
        })
        return

    ids_by_proto = defaultdict(list)
    for followee in follows:
        followee['image'] = util.get_first(followee, 'image')
        id = common.unwrap(followee.get('id'))
        proto = Protocol.for_id(id, remote=False) or from_proto
        ids_by_proto[proto].append(id)

    to_follow = []      # Users (with only key populated, no properties)
    to_follow_ids = []  # str user ids, in to_proto
    follow_counts = []  # (str protocol class, count)
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
                keys = query.fetch(keys_only=True)
                to_follow.extend(proto(key=key) for key in keys)
                follow_counts.append([f'{proto.__name__}', len(keys)])

        else:
            for proto, ids in ids_by_proto.items():
                if proto == to_proto:
                    bridged = ids
                    to_follow_ids.extend(ids)
                else:
                    query = proto.query(
                        proto.key.IN([proto(id=id).key for id in ids]),
                        proto.enabled_protocols == to_proto.LABEL,
                    )
                    bridged = query.fetch(keys_only=True)
                    to_follow.extend(proto(key=key) for key in bridged)

                follow_counts.append([f'{proto.__name__}', len(bridged)])

        for user in to_follow:
            if id := user.id_as(to_proto):
                to_follow_ids.append(id)

    for id in to_follow_ids:
        if id not in migration.followed and id not in migration.to_follow:
            migration.to_follow.append(id)

    total_bridged_follows = sum(count for _, count in follow_counts)
    follow_counts.append(['not bridged', len(follows) - total_bridged_follows])

    logger.info(f'{len(follows)} total, {follow_counts}')

    migration.review.update({
        'follows_preview_raw': follows[:FOLLOWERS_PREVIEW_LEN],
        'follow_counts': follow_counts,
        'total_bridged_follows': total_bridged_follows,
    })


def analyze_review(migration, from_auth):
    """Analyzes the follow/follower data and generates previews.

    Args:
      migration (Migration)
    """
    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    logger.info(f'Generating review for {from_auth.key_id()}')

    # generate previews of individual follower and following users (BF Users)
    followers_preview = []
    follows_preview = []
    with ndb.context.Context(bridgy_fed_ndb).use():
        for raw, preview in (
                (migration.review['followers_preview_raw'], followers_preview),
                (migration.review['follows_preview_raw'], follows_preview),
        ):
            for actor in raw[:FOLLOWERS_PREVIEW_LEN]:
                user = None
                id = actor['id']
                if from_proto.HAS_COPIES:
                    if key := models.get_original_user_key(id):
                        user = key.get()
                    else:
                        user = from_proto.get_or_create(id, allow_opt_out=True)
                else:
                    if proto := Protocol.for_id(id):
                        if proto != from_proto:
                            id = translate_user_id(id=id, from_=from_proto, to=proto)
                        user = proto.get_or_create(id, allow_opt_out=True)

                if user:
                    preview.append(user.html_link(pictures=True))

    # total counts, percentage of follows that will be kept
    follow_counts = migration.review['follow_counts']
    total_follows = sum(count for _, count in follow_counts)

    follower_counts = migration.review['follower_counts']
    total_followers = sum(count for _, count in follower_counts)

    keep_follows_pct = 100
    if total_follows > 0:
        total_bridged_follows = migration.review['total_bridged_follows']
        assert total_bridged_follows <= total_follows
        keep_follows_pct = round(total_bridged_follows / total_follows * 100)

    migration.review.update({
        'followers_preview': followers_preview,
        'follows_preview': follows_preview,
        'total_followers': total_followers,
        'total_follows': total_follows,
        'follower_counts': [['type', 'count']] + sorted(follower_counts),
        'follow_counts': [['type', 'count']] + sorted(follow_counts),
        'keep_follows_pct': keep_follows_pct,
    })


@app.get('/bluesky-password')
@require_accounts('from', 'to')
def bluesky_password(from_auth, to_auth):
    """View for entering the user's Bluesky password."""
    if not isinstance(from_auth, BlueskyAuth):
        error(f'{from_auth.key.id()} is not Bluesky')

    return render_template(
        'bluesky_password.html',
        from_auth=from_auth,
        to_auth=to_auth,
        **template_vars(),
    )


@app.route('/confirm', methods=['GET', 'POST'])
@require_accounts('from', 'to')
def confirm(from_auth, to_auth):
    """View for the migration confirmation page."""
    migration = Migration.get(from_auth, to_auth)
    if not migration:
        return redirect(url('/to', from_auth))
    if migration.state and migration.state > State.review_done:
        return redirect(url('/migrate', from_auth, to_auth))

    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    to_proto = AUTH_TO_PROTOCOL[to_auth.__class__]
    to_user = get_to_user(to_auth)

    # first, do all the checks that don't add request params:
    # * if to user is already bridged back, need to disable that
    # * if to AP, and from user is already bridged, need to set alias
    if from_proto.HAS_COPIES and to_user.is_enabled(from_proto):
        return redirect(url('/disable-bridging', from_auth, to_auth))

    from_user = get_from_user(from_auth)
    if from_user.is_enabled(to_proto):
        try:
            with ndb.context.Context(bridgy_fed_ndb).use():
                to_proto.check_can_migrate_out(from_user, to_user.key.id())
        except ValueError as e:
            # WARNING: this is brittle! depends on the exact exception message
            # from ActivityPub.check_can_migrate_out
            msg = str(e)
            logger.info(msg)
            if "alsoKnownAs doesn't contain" in msg:
                return redirect(url('/set-alsoKnownAs', from_auth, to_auth))
            else:
                flash(f"{from_auth.user_display_name()} isn't ready to migrate: {msg}")
                return redirect(url('/review', from_auth, to_auth))

    # now, the checks that add request params:
    # * from Bluesky needs password
    if isinstance(from_auth, BlueskyAuth):
        if not (password := request.values.get('password')):
            return redirect(url('/bluesky-password', from_auth, to_auth))

        # ask their PDS to email them a code that we'll need for it to sign the
        # PLC update operation
        bsky = Bluesky(pds_url=from_auth.pds_url, did=from_auth.key.id(),
                       handle=from_auth.user_display_name(), app_password=password)
        try:
            bsky.client.com.atproto.identity.requestPlcOperationSignature()
        except RequestException as e:
            _, body = util.interpret_http_exception(e)
            try:
                if json_loads(body).get('error') == 'AuthFactorTokenRequired':
                    flash("Sorry, we don't support Bluesky accounts with 2FA enabled yet. <a href='https://github.com/snarfed/bounce/issues/54'>Details here.</a> Feel free to disable 2FA on your account and try again!", escape=False)
                    return redirect(url('/bluesky-password', from_auth, to_auth))
            except ValueError:
                pass

            flash(f'Login failed: {body}')
            return redirect(url('/bluesky-password', from_auth, to_auth))

        # store password-based access token, we'll use it later in /migrate
        from_auth.session = bsky.client.session
        from_auth.put()

    vars = template_vars()
    with ndb.context.Context(bridgy_fed_ndb).use():
        vars['to_user_bridged_handle'] = to_user.handle_as(from_proto)

    return render_template(
        'confirm.html',
        from_auth=from_auth,
        from_user=from_user,
        to_auth=to_auth,
        to_user=to_user,
        **vars,
    )


@app.get('/set-alsoKnownAs')
@require_accounts('from', 'to')
def set_alsoKnownAs(from_auth, to_auth):
    """View for entering the user's Bluesky password."""
    if AUTH_TO_PROTOCOL[to_auth.__class__] != ActivityPub:
        error(f'{to_auth.key.id()} is not ActivityPub')

    from_user = get_from_user(from_auth)
    with ndb.context.Context(bridgy_fed_ndb).use():
        from_ap_handle = from_user.handle_as(ActivityPub)

    settings_url = urljoin(to_auth.instance(), SETTINGS_PATH_ALIAS[to_auth.__class__])

    return render_template(
        'set_alsoKnownAs.html',
        from_auth=from_auth,
        to_auth=to_auth,
        from_ap_handle=from_ap_handle,
        settings_url=settings_url,
        **template_vars(),
    )


@app.get('/disable-bridging')
@require_accounts('from', 'to')
def disable_bridging_get(from_auth, to_auth):
    """View for disabling existing bridging."""
    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    to_user = _get_user(to_auth)

    with ndb.context.Context(bridgy_fed_ndb).use():
        follower_count = models.Follower.query(
            models.Follower.to == to_user.key,
            models.Follower.from_ >= ndb.Key(from_proto, chr(0)),
            models.Follower.from_ <= ndb.Key(from_proto, chr(255)),
        ).count()

    return render_template(
        'disable_bridging.html',
        from_auth=from_auth,
        to_auth=to_auth,
        to_user=to_user,
        from_proto=from_proto,
        follower_count=follower_count,
        **template_vars(),
    )


@app.post('/disable-bridging')
@require_accounts('from', 'to')
def disable_bridging_post(from_auth, to_auth):
    """Disable bridging for the to account."""
    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    to_user = _get_user(to_auth)

    with ndb.context.Context(bridgy_fed_ndb).use():
        # TODO? for #50
        # to_user.delete(from_proto)
        to_user.disable_protocol(from_proto)
        memcache.remote_evict(to_user.key)

    return confirm()


@app.post('/migrate')
@require_accounts('from', 'to')
def migrate_post(from_auth, to_auth):
    """Migrate handler that starts a background task.

    Post body args:
      plc_code (str, optional)
    """
    logger.info(f'Params: {list(request.values.items())}')
    logger.info(f'Migrating {from_auth.key.id()} to {to_auth.key.id()}')

    migration = Migration.get(from_auth, to_auth)

    if not migration:
        error('migration not found', status=404)
    elif not migration.state or migration.state < State.review_done:
        flash(f'Migration can only start after review is completed.')
        return redirect(url('/review', from_auth, to_auth))
    elif migration.to != to_auth.key:
        return redirect(url('/to', from_auth))

    migration.plc_code = request.values.get('plc_code')
    if migration.plc_code:
        migration.put()

    stale = util.now() - migration.updated >= STALE_TASK_AGE
    if migration.state < State.migrate_done or stale:
        if migration.state == State.review_done:
            migration.state = State.migrate_follows
        migration.put()
        migration.create_task('migrate')

    return redirect(url('/migrate', from_auth, to_auth))


@app.get('/migrate')
@require_accounts('from', 'to')
def migrate_get(from_auth, to_auth):
    """Migrate handler that shows progress or the final result."""
    migration = Migration.get(from_auth, to_auth)
    if not migration:
        error('migration not found', status=404)
    elif not migration.state or migration.state < State.review_done:
        flash(f'Migration can only start after review is completed.')
        return redirect(url('/review', from_auth, to_auth))

    template = 'migration_progress.html'
    vars = template_vars()

    if migration.state == State.migrate_done:
        if AUTH_TO_PROTOCOL[from_auth.__class__] == ActivityPub:
            template = 'activitypub_profile_move.html'
            vars.update({
                'settings_url': urljoin(from_auth.instance(),
                                        SETTINGS_PATH_MIGRATE[from_auth.__class__]),
                'docs_url': urljoin(from_auth.instance(),
                                    DOCS_URL_MIGRATE[from_auth.__class__]),
            })
        else:
            template = 'done.html'
            oauth_dropins.logout(from_auth)
            logger.info(f'logging out {from_auth.key.id()}')

    return render_template(
        template,
        ActivityPub=ActivityPub,
        from_auth=from_auth,
        to_auth=to_auth,
        to_user=get_to_user(to_auth),
        migration=migration,
        State=State,
        **vars,
    )


@app.post('/activitypub-profile-moved')
@require_accounts('from', 'to')
def activitypub_profile_moved(from_auth, to_auth):
    """Checks that a migration from ActivityPub started the profile move."""
    assert AUTH_TO_PROTOCOL[from_auth.__class__] == ActivityPub

    migration = Migration.get(from_auth, to_auth)
    if not migration:
        error('migration not found', status=404)
    elif not migration.state or migration.state < State.migrate_done:
        flash(f'Migration not done yet.')
        return redirect(url('/migrate', from_auth, to_auth))

    from_user = get_from_user(from_auth)
    with ndb.context.Context(bridgy_fed_ndb).use():
        from_user.reload_profile()

    moved_to = from_user.obj.as2.get('movedTo')
    to_user = get_to_user(to_auth)
    if moved_to == to_user.id_as(ActivityPub):
        template = 'done.html'
    else:
        template = 'activitypub_profile_move.html'
        if moved_to:
            flash(f"It looks like you moved to {moved_to}. You'll need to undo that and try again.")
        else:
            flash(f"{util.domain_from_link(from_auth.instance())} doesn't show that you've started the profile move yet. Try again?")

    vars = {
        **template_vars(),
        'settings_url': urljoin(from_auth.instance(),
                                SETTINGS_PATH_MIGRATE[from_auth.__class__]),
        'docs_url': urljoin(from_auth.instance(),
                            DOCS_URL_MIGRATE[from_auth.__class__]),
    }
    return render_template(
        template,
        ActivityPub=ActivityPub,
        from_auth=from_auth,
        to_auth=to_auth,
        to_user=get_to_user(to_auth),
        migration=migration,
        **vars,
    )


@app.post('/queue/migrate')
@cloud_tasks_only()
@require_accounts('from', 'to', logged_in=False)
def migrate_task(from_auth, to_auth):
    """Handle the migration background task."""
    logger.info(f'Params: {list(request.values.items())}')
    logger.info(f'Processing migration task for {from_auth.key.id()} {from_auth.user_display_name()} => {to_auth.user_display_name()}')
    migration = Migration.get(from_auth, to_auth)
    assert migration, (from_auth, to_auth)

    logger.info(f'  {migration.key} {migration.state.name}')
    assert migration.state >= State.migrate_follows
    if migration.state == State.migrate_done:
        return 'OK'

    migration.last_attempt = util.now()
    migration.put()

    from_user = get_from_user(from_auth)
    to_user = get_to_user(to_auth)

    # override spam filters
    with ndb.context.Context(bridgy_fed_ndb).use():
        for user in from_user, to_user:
            if user.manual_opt_out is not False:
                user.manual_opt_out = False
                user.put()

    # Process based on migration state
    if migration.state == State.migrate_follows:
        logger.info('starting migrate_follows')
        migrate_follows(migration, to_auth)
        migration.state = State.migrate_in_blobs
        migration.put()
        logger.info('finished, now at migrate_in_blobs')

    # need to migrate blobs before migrating the account, since after we've
    # deactivated the account, it no longer serves blobs or any other XRPC calls
    if migration.state == State.migrate_in_blobs:
        logger.info('starting migrate_in_blobs')
        migrate_in_blobs(from_auth)
        migration.state = State.migrate_in
        migration.put()
        logger.info('finished, now at migrate_in')

    if migration.state == State.migrate_in:
        logger.info('starting migrate_in')
        migrate_in(migration, from_auth, from_user, to_user)
        migration.state = State.migrate_out
        migration.put()
        logger.info('finished, now at migrate_out')

    if migration.state == State.migrate_out:
        logger.info('starting migrate_out')
        migrate_out(migration, from_user, to_user)
        migration.state = State.migrate_done
        migration.put()
        logger.info('finished, now at migrate_done')

    return 'OK'


def migrate_follows(migration, to_auth):
    """Creates follows in the destination account.

    Args:
      migration (Migration)
      to_auth (oauth_dropins.models.BaseAuth)
    """
    logging.info(f'Creating follows for {to_auth.key_id()}')
    to_follow = migration.to_follow
    migration.to_follow = []
    source = granary_source(to_auth, with_auth=True, **TASK_REQUESTS_KWARGS)

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


def migrate_in(migration, from_auth, from_user, to_user):
    """Migrates a source native account into Bridgy Fed to be a bridged account.

    Args:
      migration (Migration)
      from_auth (oauth_dropins.models.BaseAuth)
      from_user (models.User)
    """
    logging.info(f'Migrating {from_user.key.id()} in')

    migrate_in_kwargs = {}

    if isinstance(from_auth, BlueskyAuth):
        # use the password-based session stored earlier in /confirm, since
        # signPlcOperation (below) doesn't support OAuth DPoP tokens
        old_pds_client = from_auth._api(session_callback=bluesky_session_callback)

        # export repo from old PDS, import into BF
        #
        # note that this currently loads the repo into memory. to stream the output
        # from getRepo, we'd need to modify lexrpc.Client, but that's doable. the
        # harder part might be decoding the CAR streaming, in xrpc_repo.import_repo,
        # which currently uses carbox. maybe still doable though?
        resp = old_pds_client.com.atproto.sync.getRepo({}, did=from_auth.key.id())
        repo_car = resp.content

        logging.info(f'Importing repo from {from_auth.pds_url}')
        with ndb.context.Context(bridgy_fed_ndb).use(), \
             app.test_request_context('/migrate', headers={
                 'Authorization': f'Bearer {os.environ["REPO_TOKEN"]}',
             }):
            xrpc_repo.import_repo(repo_car)

        assert migration.plc_code
        migrate_in_kwargs = {
            'plc_code': migration.plc_code,
            'pds_client': old_pds_client,
        }

    memcache.remote_evict(to_user.key)
    if to_user.obj_key:
        memcache.remote_evict(to_user.obj_key)

    with ndb.context.Context(bridgy_fed_ndb).use():
        from_user.migrate_in(to_user, from_user.key.id(), **migrate_in_kwargs)

    memcache.remote_evict(from_user.key)


def migrate_in_blobs(from_auth):
    """Migrates a Bluesky user's blobs into Bridgy Fed's Google Cloud Storage.

    https://atproto.com/guides/account-migration#migrating-data
    https://cloud.google.com/storage/docs/uploading-objects-from-memory#storage-upload-object-from-memory-python
    https://cloud.google.com/python/docs/reference/storage/latest/google.cloud.storage.blob.Blob.html#google_cloud_storage_blob_Blob_upload_from_string

    Args:
      from_auth (BlueskyAuth)
    """
    if not isinstance(from_auth, BlueskyAuth):
        return

    if not util.domain_or_parent_in(util.domain_from_link(from_auth.pds_url),
                                    MAIN_PDS_DOMAINS):
        logger.info(f"Not migrating blobs, PDS {from_auth.pds_url} isn't Bluesky co's")
        return

    source = granary_source(from_auth)

    did = from_auth.key.id()
    logging.info(f"Migrating Bluesky account {did}'s blobs into GCS")

    client = storage.Client()
    bucket = client.bucket(CLOUD_STORAGE_BUCKET)

    # TODO: give bounce permission to BF GCS

    with ndb.context.Context(bridgy_fed_ndb).use():
        for cid in source.client.com.atproto.sync.listBlobs(did=did)['cids']:
            logger.info(f'importing {cid}')
            path = f'atproto-blobs/{cid}'
            url = urljoin(CLOUD_STORAGE_BASE_URL, f'/{CLOUD_STORAGE_BUCKET}/{path}')
            if blob := AtpRemoteBlob.get_by_id(url):
                assert blob.cid == cid
                logger.info('  already exists, skipping')
                continue

            resp = source.client.com.atproto.sync.getBlob(did=did, cid=cid)
            type = resp.headers.get('Content-Type')

            obj = bucket.blob(path)
            obj.upload_from_string(resp.content, content_type=type)
            obj.make_public()

            blob = AtpRemoteBlob(id=url, cid=cid, mime_type=type,
                                 size=len(resp.content))
            blob.generate_metadata(resp.content)
            blob.put()


def migrate_out(migration, from_user, to_user):
    """Migrates a Bridgy Fed bridged account out to a native account.

    Args:
      migration (Migration)
      from_user (models.User)
      to_user (models.User)
    """
    logging.info(f'Migrating bridged account {from_user.key.id()} out to {to_user.key.id()}')

    with ndb.context.Context(bridgy_fed_ndb).use():
        to_proto = to_user.__class__
        if from_user.is_enabled(to_proto):
            to_user.migrate_out(from_user, to_user.key.id())

    from_proto = from_user.__class__
    if from_proto.HAS_COPIES:
        # connect to account to from account
        while existing := to_user.get_copy(from_proto):
            copy = models.Target(protocol=from_proto.LABEL, uri=existing)
            logger.warning(f'Overwriting {to_user.key.id()} {copy}')
            to_user.remove('copies', copy)

        # TODO: will probably need to change for migrating from non-ATProto (ie
        # non-portable-identity) protocols
        logger.info(f'Setting {to_user.key.id()} {from_proto.LABEL} copy to {from_user.key.id()}')
        with ndb.context.Context(bridgy_fed_ndb).use():
            to_user.add('copies', models.Target(protocol=from_proto.LABEL,
                                                uri=from_user.key.id()))
            to_user.put()

    with ndb.context.Context(bridgy_fed_ndb).use():
        to_user.enable_protocol(from_proto)
        from_proto.bot_maybe_follow_back(to_user)

    memcache.remote_evict(to_user.key)


# Used for testing access to Bridgy Fed's memcache. Doesn't currently work.
# See section at end of README.md.
#
# @app.get('/admin/memcache-get')
# def memcache_get():
#     logger.info(f'memcache get {memcache.memcache.server}')
#     print(f'memcache get {memcache.memcache.server}', file=sys.stderr)
#     if request.headers.get('Authorization') != app.config['SECRET_KEY']:
#         return '', 401

#     if key := request.values.get('key'):
#         return repr(Key(urlsafe=key).get(use_cache=False, use_datastore=False,
#                                          use_global_cache=True))
#     elif raw := request.values.get('raw'):
#         return repr(memcache.memcache.get(raw))
#     else:
#         error('either key or raw are required')


@app.get('/admin/activity')
def admin_activity():
    # maps string platform to count
    login_counts = {
        cls.__name__.removesuffix('Auth'): cls.query().count()
        for cls in AUTH_TO_PROTOCOL.keys()
    }

    # list of auth entities
    recent_logins = sorted(
        MastodonAuth.query().order(-MastodonAuth.updated).fetch(10)
          + PixelfedAuth.query().order(-PixelfedAuth.updated).fetch(10)
          + BlueskyAuth.query().order(-BlueskyAuth.updated).fetch(10),
        key=lambda auth: auth.updated, reverse=True)[:10]

    # maps string state to count
    migration_counts = defaultdict(int)
    for m in Migration.query():
        migration_counts[m.state.name if m.state else 'not started'] += 1

    # list of Migrations
    recent_migrations = Migration.query().order(-Migration.updated).fetch(10)

    auth_keys = sum(([m.from_, m.to] for m in recent_migrations), start=[])
    auths = ndb.get_multi(auth_keys)

    # list of Migrations with from_auth, to_auth attrs
    for m in recent_migrations:
        m.from_auth = auths.pop(0)
        m.to_auth = auths.pop(0)
    assert not auths

    return render_template(
        'activity.html',
        login_counts=login_counts,
        recent_logins=recent_logins,
        migration_counts=migration_counts,
        recent_migrations=recent_migrations,
        pytz=pytz,
    )


#
# OAuth
#
class MastodonStart(FlashErrors, oauth_dropins.mastodon.Start):
    DEFAULT_SCOPE = 'read:accounts read:follows read:search write:follows'
    REDIRECT_PATHS = (
        '/oauth/mastodon/finish/from',
        '/oauth/mastodon/finish/to',
    )

    def app_name(self):
        return 'Bounce'

    def app_url(self):
        return 'https://bounce.anew.social/'

class MastodonCallback(FlashErrors, oauth_dropins.mastodon.Callback):
    pass


class PixelfedStart(FlashErrors, oauth_dropins.pixelfed.Start):
    # no granular scopes yet. afaict the available scopes aren't documented at all :(
    # https://github.com/pixelfed/pixelfed/issues/2102#issuecomment-609474544
    DEFAULT_SCOPE = 'read write'
    REDIRECT_PATHS = (
        '/oauth/pixelfed/finish/from',
        '/oauth/pixelfed/finish/to',
    )

    def app_name(self):
        return 'Bounce'

    def app_url(self):
        return 'https://bounce.anew.social/'

class PixelfedCallback(FlashErrors, oauth_dropins.pixelfed.Callback):
    pass


# class ThreadsStart(FlashErrors, oauth_dropins.threads.Start):
#     TODO: scopes

# class ThreadsCallback(FlashErrors, oauth_dropins.threads.Callback):
#     pass


app.add_url_rule('/oauth/mastodon/start/from', view_func=MastodonStart.as_view(
                     '/oauth/mastodon/start/from', '/oauth/mastodon/finish/from'),
                 methods=['POST'])
app.add_url_rule('/oauth/mastodon/finish/from', view_func=MastodonCallback.as_view(
                     '/oauth/mastodon/finish/from', '/to'))
app.add_url_rule('/oauth/mastodon/start/to', view_func=MastodonStart.as_view(
                     '/oauth/mastodon/start/to', '/oauth/mastodon/finish/to'),
                 methods=['POST'])
app.add_url_rule('/oauth/mastodon/finish/to', view_func=MastodonCallback.as_view(
                     '/oauth/mastodon/finish/to', '/review'))

app.add_url_rule('/oauth/pixelfed/start/from', view_func=PixelfedStart.as_view(
                     '/oauth/pixelfed/start/from', '/oauth/pixelfed/finish/from'),
                 methods=['POST'])
app.add_url_rule('/oauth/pixelfed/finish/from', view_func=PixelfedCallback.as_view(
                     '/oauth/pixelfed/finish/from', '/to'))
app.add_url_rule('/oauth/pixelfed/start/to', view_func=PixelfedStart.as_view(
                     '/oauth/pixelfed/start/to', '/oauth/pixelfed/finish/to'),
                 methods=['POST'])
app.add_url_rule('/oauth/pixelfed/finish/to', view_func=PixelfedCallback.as_view(
                     '/oauth/pixelfed/finish/to', '/review'))

# app.add_url_rule('/oauth/threads/start/from', view_func=ThreadsStart.as_view(
#                      '/oauth/threads/start/from', '/oauth/threads/finish/from'),
#                  methods=['POST'])
# app.add_url_rule('/oauth/threads/finish/from', view_func=ThreadsCallback.as_view(
#                      '/oauth/threads/finish/from', '/to'))
# app.add_url_rule('/oauth/threads/start/to', view_func=ThreadsStart.as_view(
#                      '/oauth/threads/start/to', '/oauth/threads/finish/to'),
#                  methods=['POST'])
# app.add_url_rule('/oauth/threads/finish/to', view_func=ThreadsCallback.as_view(
#                      '/oauth/threads/finish/to', '/review'))


#
# Bluesky OAuth
#
def bluesky_oauth_client_metadata():
    base_url = (f'https://{DOMAIN}/' if request.host.endswith('.appspot.com')
                else request.host_url)
    return {
        **oauth_dropins.bluesky.CLIENT_METADATA_TEMPLATE,
        'client_id': urljoin(base_url, '/oauth/bluesky/client-metadata.json'),
        'client_name': 'Bounce',
        'client_uri': base_url,
        'redirect_uris': [
            urljoin(base_url, '/oauth/bluesky/finish/from'),
            urljoin(base_url, 'oauth/bluesky/finish/to'),
        ],
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


app.add_url_rule('/oauth/bluesky/start/from', view_func=BlueskyOAuthStart.as_view(
    '/oauth/bluesky/start/from', '/oauth/bluesky/finish/from'), methods=['POST'])
app.add_url_rule('/oauth/bluesky/finish/from', view_func=BlueskyOAuthCallback.as_view(
    '/oauth/bluesky/finish/from', '/to'))
app.add_url_rule('/oauth/bluesky/start/to', view_func=BlueskyOAuthStart.as_view(
    '/oauth/bluesky/start/to', '/oauth/bluesky/finish/to'), methods=['POST'])
app.add_url_rule('/oauth/bluesky/finish/to', view_func=BlueskyOAuthCallback.as_view(
    '/oauth/bluesky/finish/to', '/review'))
