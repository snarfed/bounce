"""UI pages."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from itertools import chain
import json
import logging
import os
from pathlib import Path
import sys

from arroba import xrpc_repo
from arroba.datastore_storage import DatastoreStorage
import arroba.server
from flask import flash, Flask, redirect, render_template, request
import flask_gae_static
from google.cloud import ndb
from granary import as2
from granary.bluesky import Bluesky
from granary.mastodon import Mastodon
from granary.pixelfed import Pixelfed
import lexrpc
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
from oauth_dropins.webutil.flask_util import (
    error,
    FlashErrors,
    Found,
    get_required_param,
)
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

arroba.server.storage = DatastoreStorage(ndb_client=bridgy_fed_ndb)


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

    Key id is '[from auth entity id] [to protocol Bridgy Fed label]', eg
    'did:plc:alice activitypub'.
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
        return super().get_or_insert(id, **kwargs)


def template_vars(oauth_path_suffix=''):
    """Returns base template vars common to most views.

    Args:
      oauth_path_suffix: appended to the end of the OAuth start URL paths
    """
    auths = []
    for auth in ndb.get_multi(oauth_dropins.get_logins()):
        if auth:
            user_json = json.loads(auth.user_json)
            auth.url = granary_source(auth).to_as1_actor(user_json).get('url')
            auths.append(auth)

    return {
        'auths': auths,
    }


def require_accounts(from_params, to_params=None):
    """Decorator that requires and loads both from and (optionally) to auth entities.

    Passes both entities as positional args to the function, as oauth-dropins auth
    entities. Also performs sanity checks:
    * Both must be logged in
    * They must be different protocols
    * If a Bluesky account is involved, it can't be a did:web

    Args:
      from_params (str or sequence of str): HTTP query param(s) with the url-safe ndb
        key for the from auth entity
      to_params (str or sequence of str): HTTP query param(s) with the url-safe ndb key
        for the to auth entity
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
        if key in oauth_dropins.get_logins():
            if auth := key.get():
                return auth

        logger.warning(f'not logged in for {key}')
        raise Found(location='/')

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
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
                if (isinstance(auth, oauth_dropins.bluesky.BlueskyAuth)
                        and auth.key.id().startswith('did:web:')):
                    flash('Sorry, did:webs are not currently supported.')
                    return redirect('/', code=302)

            # TODO: load to user, check state, check that it's not already bridged
            # (move check from /review)
            # load migration, check that it's not already done

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def granary_source(auth, with_auth=False):
    """Returns a granary source instance for a given auth entity.

    Args:
      auth (oauth_dropins.models.BaseAuth)
      with_auth (bool)

    Returns:
      granary.source.Source:
    """
    if isinstance(auth, (oauth_dropins.mastodon.MastodonAuth,
                         oauth_dropins.pixelfed.PixelfedAuth)):
        return Mastodon(instance=auth.instance(), access_token=auth.access_token_str,
                        user_id=auth.user_id())

    elif isinstance(auth, oauth_dropins.bluesky.BlueskyAuth):
        extra = {}
        if with_auth:
            oauth_client = oauth_dropins.bluesky.oauth_client_for_pds(
                bluesky_oauth_client_metadata(), auth.pds_url)
            token = DPoPTokenSerializer.default_loader(auth.dpop_token)
            dpop_auth = OAuth2AccessTokenAuth(client=oauth_client, token=token)
            extra['auth'] = dpop_auth

        return Bluesky(pds_url=auth.pds_url, handle=auth.user_display_name(),
                       did=auth.key.id(), **extra)


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
            return ActivityPub.get_or_create(json.loads(auth.user_json)['uri'],
                                             allow_opt_out=True)
        elif isinstance(auth, oauth_dropins.bluesky.BlueskyAuth):
            return ATProto.get_or_create(auth.key.id(), allow_opt_out=True)


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
    return redirect('/', code=302)


@app.get('/from')
def choose_from():
    """Choose account to migrate from."""
    vars = template_vars()

    accounts = [a for a in vars['auths'] if isinstance(a, oauth_dropins.bluesky.BlueskyAuth)]
    for acct in accounts:
        acct.url = f'/to?from={acct.key.urlsafe().decode()}'

    return render_template(
        'accounts.html',
        body_id='from',
        accounts=accounts,
        bluesky_button=oauth_dropins.bluesky.Start.button_html(
            '/oauth/bluesky/start/from',
            image_prefix='/oauth_dropins_static/'),
        # mastodon_button=oauth_dropins.mastodon.Start.button_html(
        #     '/oauth/mastodon/start/from',
        #     image_prefix='/oauth_dropins_static/'),
        # pixelfed_button=oauth_dropins.pixelfed.Start.button_html(
        #     '/oauth/pixelfed/start/from',
        #     image_prefix='/oauth_dropins_static/'),
        # threads_button=oauth_dropins.threads.Start.button_html(
        #     '/oauth/threads/start/from',
        #     image_prefix='/oauth_dropins_static/'),
        **vars,
    )


@app.get('/to')
@require_accounts(('from', 'auth_entity'))
def choose_to(from_auth):
    """Choose account to migrate to."""
    if from_auth.key.id().startswith('did:web:'):
        flash('Sorry, did:webs are not currently supported.')
        return redirect('/', code=302)

    vars = template_vars()
    from_key = from_auth.key.urlsafe().decode()

    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    accounts = [auth for auth in vars['auths']
                if from_proto != AUTH_TO_PROTOCOL[auth.__class__]]
    for acct in accounts:
        acct.url = f'/review?from={from_key}&to={acct.key.urlsafe().decode()}'

    state = f'<input type="hidden" name="state" value="{from_key}" />'
    return render_template(
        'accounts.html',
        body_id='to',
        from_auth=from_auth,
        from_proto=from_proto,
        accounts=accounts,
        # bluesky_button=oauth_dropins.bluesky.Start.button_html(
        #     '/oauth/bluesky/start/to',
        #     image_prefix='/oauth_dropins_static/', form_extra=state),
        mastodon_button=oauth_dropins.mastodon.Start.button_html(
            '/oauth/mastodon/start/to',
            image_prefix='/oauth_dropins_static/', form_extra=state),
        pixelfed_button=oauth_dropins.pixelfed.Start.button_html(
            '/oauth/pixelfed/start/to',
            image_prefix='/oauth_dropins_static/', form_extra=state),
        # threads_button=oauth_dropins.threads.Start.button_html(
        #     '/oauth/threads/start/to',
        #     image_prefix='/oauth_dropins_static/', form_extra=state),
        **vars,
    )


@app.get('/review')
@require_accounts(('from', 'state'), ('to', 'auth_entity'))
def review(from_auth, to_auth):
    """Review an account's followers and follows."""
    from_proto = AUTH_TO_PROTOCOL[from_auth.__class__]
    assert from_proto in (ActivityPub, ATProto)
    to_proto = AUTH_TO_PROTOCOL[to_auth.__class__]
    assert to_proto in (ActivityPub, ATProto)

    cache_key = f'review-html-{from_auth.key.id()}-{to_auth.key.id()}'
    if 'force' not in request.args:
        if cached := Cache.get(cache_key):
            logger.info(f'Returning cached review for {from_auth.key.id()}')
            return cached

    logger.info(f'Reviewing {from_auth.key.id()} {from_auth.user_display_name()} => {to_auth.site_name()}')

    migration = Migration.get_or_insert(from_auth, to_auth)
    if migration.state != 'follows':
        flash(f'{from_auth.user_display_name()} has already begun migrating to {migration.to.get().user_display_name()}.')
        return redirect(f'/to?from={from_auth.key.urlsafe().decode()}', code=302)
    elif migration.to != to_auth.key:
        # new migration or new (different) to account, reset progress
        migration.to = to_auth.key
        migration.followed = []
        migration.to_follow = []

    to_user = get_user(to_auth)
    if to_user.is_enabled(from_proto):
        flash(f'{to_auth.user_display_name()} is already bridged to {from_proto.PHRASE}. Please <a href="https://fed.brid.gy/docs#opt-out">disable that</a> first or choose another account.')
        # TODO: remove from logins
        return redirect(f'/to?from={from_auth.key.urlsafe().decode()}', code=302)

    source = granary_source(from_auth, with_auth=True)
    from_auth.url = source.to_as1_actor(json.loads(from_auth.user_json)).get('url')

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
    migration.put()

    total_bridged = sum(count for _, count in follow_counts)
    follow_counts.append(['not bridged', len(follows) - total_bridged])

    logger.info(f'{len(follows)} total, {follow_counts}')

    # preprocess actors
    if from_proto == ActivityPub:
        for f in followers + follows:
            f['username'] = as2.address(as2.from_as1(f))

    keep_follows_pct = 100
    if follows:
        keep_follows_pct = round(total_bridged / len(follows) * 100)

    html = render_template(
        'review.html',
        from_auth=from_auth,
        to_auth=to_auth,
        followers=followers,
        follows=follows,
        follower_counts=[['type', 'count']] + sorted(follower_counts),
        follow_counts=[['type', 'count']] + sorted(follow_counts),
        keep_follows_pct=keep_follows_pct,
        **template_vars(),
    )
    Cache.put(cache_key, html, expire=timedelta(days=30))
    return html


@app.get('/bluesky-password')
@require_accounts('from', 'to')
def bluesky_password(from_auth, to_auth):
    """View for entering the user's Bluesky password."""
    if not isinstance(from_auth, oauth_dropins.bluesky.BlueskyAuth):
        error(f'{from_auth.key.id()} is not Bluesky')

    return render_template(
        'bluesky_password.html',
        from_auth=from_auth,
        to_auth=to_auth,
        **template_vars(),
    )


@app.post('/confirm')
@require_accounts('from', 'to')
def confirm(from_auth, to_auth):
    """View for the migration confirmation page."""
    if isinstance(from_auth, oauth_dropins.bluesky.BlueskyAuth):
        # ask their PDS to email them a code that we'll need for it to sign the
        # PLC update operation
        bsky = Bluesky(pds_url=from_auth.pds_url,
                       did=from_auth.key.id(),
                       handle=from_auth.user_display_name(),
                       app_password=get_required_param('password'))
        try:
            bsky.client.com.atproto.identity.requestPlcOperationSignature()
        except RequestException as e:
            _, body = util.interpret_http_exception(e)
            flash(f'Login failed: {body}')
            return redirect(f'/bluesky-password?from={from_auth.key.urlsafe().decode()}&to={to_auth.key.urlsafe().decode()}')

        # store password-based access token, we'll use it later in /migrate
        from_auth.session = bsky.client.session
        from_auth.put()

    return render_template(
        'confirm.html',
        from_auth=from_auth,
        to_auth=to_auth,
        **template_vars(),
    )


@app.post('/migrate')
@require_accounts('from', 'to')
def migrate(from_auth, to_auth):
    """Migration handler."""
    logger.info(f'Migrating {from_auth.key.id()} {to_auth.key.id()}')

    migration = Migration.get(from_auth, to_auth)
    if not migration:
        error('migration not found', status=404)
    elif migration.state == 'done':
        flash(f'{from_auth.user_display_name()} has already been migrated.')
        return redirect('/from')

    migration.last_attempt = util.now()
    migration.put()

    from_user = get_user(from_auth)
    to_user = get_user(to_auth)
    assert from_user.__class__ != to_user.__class__, (from_user, to_user)

    if migration.state == 'follows':
        migrate_follows(migration, to_auth)
        migration.state = 'in'
        migration.put()

    if migration.state == 'in':
        migrate_in(migration, from_auth, from_user, to_user)
        migration.state = 'out'
        migration.put()

    if migration.state == 'out':
        migrate_out(migration, from_user, to_user)
        migration.state = 'done'
        migration.put()

    # TODO: update profile
    # TODO: update handle ? in same signPlcOperation ?

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
    source = granary_source(to_auth, with_auth=True)

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
    logging.info(f'Migrating {from_user.key.id()} in to bridged account TODO')

    migrate_in_kwargs = {}

    if isinstance(from_auth, oauth_dropins.bluesky.BlueskyAuth):
        # export repo from old PDS, import into BF
        #
        # note that this currently loads the repo into memory. to stream the output
        # from getRepo, we'd need to modify lexrpc.Client, but that's doable. the
        # harder part might be decoding the CAR streaming, in xrpc_repo.import_repo,
        # which currently uses carbox. maybe still doable though?
        old_pds_client = from_auth._api()
        repo_car = old_pds_client.com.atproto.sync.getRepo({}, did=from_auth.key.id())

        logging.info(f'Importing repo from {from_auth.pds_url}')
        with ndb.context.Context(bridgy_fed_ndb).use(), \
             app.test_request_context('/migrate', headers={
                 'Authorization': f'Bearer {os.environ["REPO_TOKEN"]}',
             }):
            xrpc_repo.import_repo(repo_car)

        migrate_in_kwargs = {
            'plc_code': get_required_param('plc-code'),
            'pds_client': old_pds_client,
        }

    with ndb.context.Context(bridgy_fed_ndb).use():
         from_user.migrate_in(to_user, from_user.key.id(), **migrate_in_kwargs)


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
        if not from_user.is_enabled(to_proto):
            from_user.enable_protocol(to_proto)

        # TODO: tell the user to add the bridged Bluesky account to their Mastodon
        # account's alsoKnownAs aliases
        to_user.migrate_out(from_user, to_user.key.id())

    from_proto = from_user.__class__
    if from_proto.HAS_COPIES:
        # connect to account to from account
        while existing := to_user.get_copy(from_proto):
            logger.warning(f'Overwriting {to_user.key.id()} {from_proto.LABEL} copy {existing}')
            to_user.remove('copies', existing)

        # TODO: will probably need to change for migrating from non-ATProto (ie
        # non-portable-identity) protocols
        logger.info(f'Setting {to_user.key.id()} {from_proto.LABEL} copy to {from_user.key.id()}')
        with ndb.context.Context(bridgy_fed_ndb).use():
            to_user.add('copies', models.Target(protocol=from_proto.LABEL,
                                                uri=from_user.key.id()))
            # TODO: to_user.obj.add copy of profile
            to_user.put()
            to_user.enable_protocol(from_proto)
            from_proto.bot_follow(to_user)


#
# OAuth
#
class MastodonStart(FlashErrors, oauth_dropins.mastodon.Start):
    DEFAULT_SCOPE = 'profile read:follows read:search write:follows'

class MastodonCallback(FlashErrors, oauth_dropins.mastodon.Callback):
    pass

class PixelfedStart(FlashErrors, oauth_dropins.pixelfed.Start):
    # no granular scopes yet. afaict the available scopes aren't documented at all :(
    # https://github.com/pixelfed/pixelfed/issues/2102#issuecomment-609474544
    DEFAULT_SCOPE = 'read write'

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
    return {
        **oauth_dropins.bluesky.CLIENT_METADATA_TEMPLATE,
        'client_id': f'{request.host_url}oauth/bluesky/client-metadata.json',
        'client_name': 'Bounce',
        'client_uri': request.host_url,
        'redirect_uris': [
            f'{request.host_url}oauth/bluesky/finish/from',
            f'{request.host_url}oauth/bluesky/finish/to',
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
