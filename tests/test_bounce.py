"""Unit tests for bounce.py."""
import copy
from datetime import timedelta
import json
import os
from unittest import TestCase
from unittest.mock import ANY, call, patch
from urllib.parse import quote

from arroba import did, server
from arroba.tests.test_xrpc_repo import (
    SNARFED2_CAR,
    SNARFED2_DID,
    SNARFED2_DID_DOC,
    SNARFED2_HEAD,
    SNARFED2_RECORDS,
)
from Crypto.PublicKey import RSA
from flask import get_flashed_messages, session
from google.cloud import ndb
from granary import as2
from granary.source import html_to_text
import granary.mastodon
import oauth_dropins
from oauth_dropins.bluesky import BlueskyAuth
from oauth_dropins.mastodon import MastodonApp, MastodonAuth
from oauth_dropins.views import LOGINS_SESSION_KEY
from oauth_dropins.webutil import flask_util, testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client, tasks_client
from oauth_dropins.webutil.testutil import (
    Asserts,
    NOW,
    requests_response,
    suppress_warnings,
)
import requests
from requests_oauth2client import (
  DPoPKey,
  DPoPToken,
  DPoPTokenSerializer,
  OAuth2AccessTokenAuth,
  OAuth2Client,
)

# from Bridgy Fed
import activitypub
from activitypub import ActivityPub
from atproto import ATProto
from common import long_to_base64, TASKS_LOCATION
import ids
import memcache
import models
from models import Object, Target
import protocol
from web import Web

from bounce import app, bridgy_fed_ndb, Migration, State

DPOP_TOKEN = DPoPToken(access_token='towkin', _dpop_key=DPoPKey.generate())
DPOP_TOKEN_STR = DPoPTokenSerializer.default_dumper(DPOP_TOKEN)

DID_DOC = {
    'id': 'did:plc:alice',
    'alsoKnownAs': ['at://al.ice'],
    'verificationMethod': [{
        'id': 'did:plc:alice#atproto',
        'type': 'Multikey',
        'controller': 'did:plc:alice',
        'publicKeyMultibase': 'did:key:xyz',
    }],
    'service': [{
        'id': '#atproto_pds',
        'type': 'AtprotoPersonalDataServer',
        'serviceEndpoint': 'https://some.pds',
    }],
}
SNARFED2_DID_DOC = {  # add #atproto_pds
    **DID_DOC,
    **SNARFED2_DID_DOC,
}
ALICE_BSKY_PROFILE = {
    'uri': 'at://did:plc:alice/app.bsky.actor.profile/self',
    'cid': 'abcdefgh',
    'value': {
        '$type': 'app.bsky.actor.profile',
        'displayName': 'Alice',
        'avatar': {
            '$type': 'blob',
            'ref': {'$link': 'bafkreicqp'},
        },
    },
}
BOB_BSKY_PROFILE = copy.deepcopy(ALICE_BSKY_PROFILE)
BOB_BSKY_PROFILE['value']['displayName'] = 'Bawb'
ALICE_AP_ACTOR = {
    'type': 'Person',
    'id': 'http://in.st/users/alice',
    'image': 'http://in.st/@alice/pic',
}
ALICE_WEBFINGER = {
    'subject': '@alice@in.st',
}

ALICE_AP_HTML = '<span class="logo" title="ActivityPub"><img src="/static/fediverse_logo.svg"></span> <a class="h-card u-author" rel="me" href="http://in.st/users/alice" title="@alice@in.st"><img src="http://in.st/@alice/pic" class="profile"> @alice@in.st</a>'
ALICE_BS_HTML = '<span class="logo" title="ATProto"><img src="/oauth_dropins_static/bluesky.svg"></span> <a class="h-card u-author" rel="me" href="https://bsky.app/profile/al.ice" title="al.ice">al.ice</a>'
BOB_AP_HTML = '<span class="logo" title="ActivityPub"><img src="/static/fediverse_logo.svg"></span> <a class="h-card u-author" rel="me" href="http://inst/bob" title="bawb"><span style="unicode-bidi: isolate">bawb</span></a>'
BOB_BS_HTML = '<span class="logo" title="ATProto"><img src="/oauth_dropins_static/bluesky.svg"></span> <a class="h-card u-author" rel="me" href="https://bsky.app/profile/ba.wb" title="Bawb &middot; ba.wb"><span style="unicode-bidi: isolate">Bawb</span> &middot; ba.wb</a>'
EVE_WEB_HTML = '<span class="logo" title="Web">🌐</span> <a class="h-card u-author" rel="me" href="https://e.ve/" title="e.ve">e.ve</a>'
REVIEW_DATA_MASTODON_TO_BLUESKY = {
    'followers_preview': [ALICE_AP_HTML, BOB_BS_HTML],
    'follows_preview': [ALICE_AP_HTML, BOB_BS_HTML, EVE_WEB_HTML],
    # 'followers_preview_raw': [ALICE_AS1, BOB_AS1],
    # 'follows_preview_raw': [ALICE_AS1, BOB_AS1, EVE_AS1],
    'total_followers': '2',
    'total_follows': '3',
    'total_bridged_follows': 2,
    'follower_counts': [
        ['type', 'count'],
        ['ATProto', 1],
        ['ActivityPub', 1],
    ],
    'follow_counts': [
        ['type', 'count'],
        ['ATProto', 1],
        ['ActivityPub', 0],
        ['Web', 1],
        ['not bridged', 1],
    ],
    'keep_follows_pct': 67,
}
REVIEW_DATA_BLUESKY_TO_MASTODON = {
    'followers_preview': [ALICE_BS_HTML, BOB_AP_HTML],
    'follows_preview': [ALICE_BS_HTML, BOB_AP_HTML, EVE_WEB_HTML],
    # 'followers_preview_raw': [ALICE_AS1, BOB_AS1],
    # 'follows_preview_raw': [ALICE_AS1, BOB_AS1, EVE_AS1],
    'total_followers': '2',
    'total_follows': '3',
    'total_bridged_follows': 2,
    'follower_counts': [
        ['type', 'count'],
        ['ATProto', 1],
        ['ActivityPub', 1],
        ['Web', 0],
    ],
    'follow_counts': [
        ['type', 'count'],
        ['ATProto', 1],
        ['ActivityPub', 1],
        ['Web', 0],
        ['not bridged', 1],
    ],
    'keep_follows_pct': 67,
}

class BounceTest(TestCase, Asserts):

    def setUp(self):
        super().setUp()
        suppress_warnings()

        self.client = app.test_client()
        self.client.__enter__()

        # clear datastore
        requests.post(f'http://{ndb_client.host}/reset')
        self.ndb_context = ndb_client.context()
        self.ndb_context.__enter__()

        did.resolve_handle.cache.clear()
        did.resolve_plc.cache.clear()
        did.resolve_web.cache.clear()
        ids.web_ap_base_domain.cache.clear()
        memcache.memcache.close()
        memcache.pickle_memcache.close()
        memcache.global_cache.clear()
        models.get_original_object_key.cache_clear()
        models.get_original_user_key.cache_clear()
        protocol.Protocol.for_id.cache.clear()
        protocol.Protocol.for_handle.cache.clear()

        os.environ.setdefault('REPO_TOKEN', 'reepow-towkin')
        util.now = lambda **kwargs: NOW

    def tearDown(self):
        self.ndb_context.__exit__(None, None, None)
        self.client.__exit__(None, None, None)
        super().tearDown()

    @staticmethod
    def make_bot_users():
        key = RSA.generate(1024)
        with ndb.context.Context(bridgy_fed_ndb).use():
            for domain in 'ap.brid.gy', 'bsky.brid.gy', 'fed.brid.gy':
                Web(id=domain, mod=long_to_base64(key.n),
                    public_exponent=long_to_base64(key.e),
                    private_exponent=long_to_base64(key.d)).put()


    def make_mastodon(self, sess, name='alice', login=True):
        app = MastodonApp(instance='http://in.st/', data='{}').put()
        user_json = json.dumps({
            'id': '234',
            'uri':f'http://in.st/users/{name}',
            'avatar_static': f'http://in.st/@{name}/pic',
        })
        auth = MastodonAuth(id=f'@{name}@in.st', access_token_str='towkin', app=app,
                            user_json=user_json).put()

        if login:
            sess.setdefault(LOGINS_SESSION_KEY, []).append(
                ('MastodonAuth', f'@{name}@in.st'))

        return auth

    def make_bluesky(self, sess, did='did:plc:alice', login=True):
        user_json = json.dumps({
            '$type': 'app.bsky.actor.defs#profileView',
            'handle': 'al.ice',
            'avatar': 'http://alice/pic',
        })
        auth = BlueskyAuth(id=did, pds_url='https://some.pds/',
                           user_json=user_json, dpop_token=DPOP_TOKEN_STR).put()

        if login:
            sess.setdefault(LOGINS_SESSION_KEY, []).append(('BlueskyAuth', did))

        return auth

    def _req(self, fn, path, from_key=None, to_key=None, **kwargs):
        data = kwargs
        if from_key:
            data['from'] = from_key.urlsafe().decode()
        if to_key:
            data['to'] = to_key.urlsafe().decode()

        param = 'query_string' if fn == self.client.get else 'data'

        return fn(path, headers={'X-AppEngine-TaskName': 'foo'}, **{param: data})

    def get(self, path, *args, **kwargs):
        return self._req(self.client.get, path, *args, **kwargs)

    def post(self, path, *args, **kwargs):
        return self._req(self.client.post, path, *args, **kwargs)

    def assert_task(self, mock_create_task, queue, from_auth, to_auth):
        # somewhat duplicated from bridgy-fed.tests.testutil.TestCase. if it gets any
        # more complicated, switch to reusing that
        calls = mock_create_task.call_args_list
        self.assertEqual(1, len(calls))

        kwargs = calls[0][1]
        self.assertEqual(f'projects//locations/{TASKS_LOCATION}/queues/{queue}',
                         kwargs['parent'])
        self.assertEqual(
            f'from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}'.encode(),
            kwargs['task']['app_engine_http_request']['body'])

    def test_front_page(self):
        got = self.client.get('/')
        self.assert_equals(200, got.status_code)

    def test_front_page_login_missing_app_gets_logged_out(self):
        with self.client.session_transaction() as sess:
            bsky = self.make_bluesky(sess)
            masto = self.make_mastodon(sess)

        self.assertEqual([
            ('BlueskyAuth', bsky.id()),
            ('MastodonAuth', masto.id()),
        ], sess[LOGINS_SESSION_KEY])

        masto.get().app.delete()

        got = self.client.get('/')
        self.assert_equals(200, got.status_code)
        self.assertEqual([
            ('BlueskyAuth', bsky.id()),
        ], session[LOGINS_SESSION_KEY])

    def test_logout(self):
        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [('BlueskyAuth', 'did:abc')]

        resp = self.client.post('/logout')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])
        self.assertNotIn(LOGINS_SESSION_KEY, session)

    def test_from(self):
        with self.client.session_transaction() as sess:
            self.make_bluesky(sess)
            self.make_mastodon(sess)

        resp = self.client.get('/from')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)

        self.assert_multiline_in("""\
<a id="logins" href="/from">
<nobr title="Bluesky: al.ice">""", body, ignore_blanks=True)
        # TODO: re-enable when we add fediverse => Bluesky support
#         self.assert_multiline_in("""\
# <nobr title="Mastodon: @alice@in.st">""", body)

        self.assert_multiline_in("""\
<a class="actor" href="/to?from=agNhcHByHgsSC0JsdWVza3lBdXRoIg1kaWQ6cGxjOmFsaWNlDA">
<img src="/oauth_dropins_static/bluesky_icon.png"
class="logo" title="Bluesky" />
<img src="http://alice/pic" class="profile">
<span style="unicode-bidi: isolate">al.ice</span>""", body)
#         self.assert_multiline_in("""\
# <img src="http://in.st/@alice/pic" class="profile">
# <span style="unicode-bidi: isolate">@alice@in.st</span>""", body)

    def test_to(self):
        with self.client.session_transaction() as sess:
            self.make_bluesky(sess)
            auth = self.make_mastodon(sess)

        resp = self.get('/to', from_key=auth)
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)

        self.assert_multiline_in("""\
<a class="actor" href="/review?from=agNhcHByHgsSDE1hc3RvZG9uQXV0aCIMQGFsaWNlQGluLnN0DA&to=agNhcHByHgsSC0JsdWVza3lBdXRoIg1kaWQ6cGxjOmFsaWNlDA">
<img src="/oauth_dropins_static/bluesky_icon.png"
class="logo" title="Bluesky" />
<img src="http://alice/pic" class="profile">
<span style="unicode-bidi: isolate">al.ice</span>""", body)
        self.assertNotIn("""\
<img src="http://in.st/@alice/pic" class="profile">
<span style="unicode-bidi: isolate">@alice@in.st</span>""", body)

    def test_to_did_web(self):
        with self.client.session_transaction() as sess:
            auth = self.make_bluesky(sess, did='did:web:alice.com')

        resp = self.get('/to', from_key=auth)
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])
        self.assertEqual(['Sorry, did:webs are not currently supported.'],
                         get_flashed_messages())

    def test_review_not_logged_in(self):
        resp = self.get('/review', BlueskyAuth(id='did:foo').key,
                        MastodonAuth(id='@bar@ba.z').key)
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])

    def test_review_no_auth_param(self):
        resp = self.get('/review')
        self.assertEqual(400, resp.status_code)

    def test_review_to_account_is_bridged(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        with ndb.context.Context(bridgy_fed_ndb).use():
            ActivityPub(id='http://in.st/users/alice',
                        enabled_protocols=['atproto']).put()

        resp = self.get('/review', from_auth, to_auth)
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/to?from={from_auth.urlsafe().decode()}',
                         resp.headers['Location'])
        flashed = get_flashed_messages()
        self.assertTrue(flashed[0].startswith('@alice@in.st is already bridged to Bluesky.'), flashed)

    def test_review_to_account_ineligible_for_bridging(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        with ndb.context.Context(bridgy_fed_ndb).use():
            obj = Object(id='profile', as2={'displayName': 'alice'})
            ActivityPub(id='http://in.st/users/alice', obj_key=obj.put()).put()

        resp = self.get('/review', from_auth, to_auth)
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/to?from={from_auth.urlsafe().decode()}',
                         resp.headers['Location'])
        self.assertTrue(get_flashed_messages()[0].startswith(
            "Sorry, @alice@in.st isn't eligible yet because you haven't set a profile picture."))

    def test_review_migration_in_progress(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            existing_to_auth = self.make_mastodon(sess, name='bob')
            new_to_auth = self.make_mastodon(sess)

        Migration(id='did:plc:alice activitypub', state=State.migrate_out,
                  to=existing_to_auth).put()

        resp = self.get('/review', from_auth, new_to_auth)
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/to?from={from_auth.urlsafe().decode()}',
                         resp.headers['Location'])
        self.assertEqual(['al.ice has already begun migrating to @bob@in.st.'],
                         get_flashed_messages())

    @patch.object(tasks_client, 'create_task')
    @patch('requests.get', return_value=requests_response(
        ALICE_AP_ACTOR, content_type=as2.CONTENT_TYPE))
    def test_review_starts_task(self, mock_get, mock_create_task):
        self.make_bot_users()
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        resp = self.get('/review', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)
        self.assertIn('<meta http-equiv="refresh" content="5">',
                      resp.get_data(as_text=True))

        migration = Migration.get_by_id('did:plc:alice activitypub')
        self.assertEqual(State.review_followers, migration.state)
        self.assert_task(mock_create_task, 'review', from_auth, to_auth)

    @patch.object(tasks_client, 'create_task')
    @patch('requests.get', side_effect=[
        requests_response(ALICE_AP_ACTOR, content_type=as2.CONTENT_TYPE),
        requests_response(ALICE_WEBFINGER),
        requests_response(ALICE_WEBFINGER),
    ])
    def test_review_with_stale_migration_starts_task(self, mock_get, mock_create_task):
        self.make_bot_users()
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        yesterday = NOW - timedelta(days=1)
        with patch('bounce.Migration.updated._now', return_value=yesterday):
            migration = Migration.get_or_insert(from_auth.get(), to_auth.get(),
                                                state=State.review_analyze)

        self.assertEqual(yesterday, migration.key.get().updated)

        resp = self.get('/review', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)
        self.assert_task(mock_create_task, 'review', from_auth, to_auth)
        self.assertGreater(migration.key.get().updated, yesterday)

    @patch('requests.get', side_effect=[
        requests_response(DID_DOC),  # did:plc:alice
        requests_response(ALICE_BSKY_PROFILE),
    ])
    def test_review_done_mastodon_to_bluesky(self, mock_get):
        with self.client.session_transaction() as sess:
            from_auth = self.make_mastodon(sess)
            to_auth = self.make_bluesky(sess)

        Migration.get_or_insert(from_auth.get(), to_auth.get(),
                                state=State.review_done,
                                review=REVIEW_DATA_MASTODON_TO_BLUESKY)

        resp = self.get('/review', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)

        body = resp.get_data(as_text=True)
        self.assertNotIn('<meta http-equiv="refresh" content="5">', body)
        self.assert_multiline_in("""
document.getElementById('followers-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 1]])""", body)
        self.assert_multiline_in("""
document.getElementById('follows-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 0], ["Web", 1], ["not bridged", 1]])""", body)

        text = html_to_text(body)
        self.assert_multiline_in("""
When you migrate  @alice@in.st to  al.ice ...
### You'll keep _all_ of your 2 followers.
* @alice@in.st
* Bawb · ba.wb
### You'll keep _67%_ of your 3 follows.
* @alice@in.st
* Bawb · ba.wb
* 🌐 e.ve""", text, ignore_blanks=True)
        self.assertIn('<form action="/confirm" method="get">', body)

    def test_review_done_bluesky_to_mastodon(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        with ndb.context.Context(bridgy_fed_ndb).use():
            ActivityPub(id='http://in.st/users/alice').put()

        Migration.get_or_insert(from_auth.get(), to_auth.get(),
                                state=State.review_done,
                                review=REVIEW_DATA_BLUESKY_TO_MASTODON)

        resp = self.get('/review', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)

        body = resp.get_data(as_text=True)
        self.assertNotIn('<meta http-equiv="refresh" content="5">', body)
        self.assert_multiline_in("""
document.getElementById('followers-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 1], ["Web", 0]])""", body)
        self.assert_multiline_in("""
document.getElementById('follows-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 1], ["Web", 0], ["not bridged", 1]])""", body)

        text = html_to_text(body)
        self.assert_multiline_in("""
When you migrate  al.ice to  @alice@in.st ...
### You'll keep _all_ of your 2 followers.
* al.ice
* bawb
### You'll keep _67%_ of your 3 follows.
* al.ice
* bawb
* 🌐 e.ve""", text, ignore_blanks=True)
        self.assertIn('<form action="/bluesky-password" method="get">', body)

    @patch.object(tasks_client, 'create_task')
    def test_review_done_with_new_to_bluesky_to(self, mock_create_task):
        self.make_bot_users()
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            orig_to_auth = self.make_mastodon(sess)
            new_to_auth = self.make_mastodon(sess, name='bob')

        with ndb.context.Context(bridgy_fed_ndb).use():
            ActivityPub(id='http://in.st/users/bob').put()

        Migration.get_or_insert(from_auth.get(), orig_to_auth.get(),
                                state=State.review_done, review={'orig': 'data'})

        resp = self.get('/review', from_auth, new_to_auth)
        self.assertEqual(200, resp.status_code)

        migration = Migration.get_by_id('did:plc:alice activitypub')
        self.assertEqual(from_auth, migration.from_)
        self.assertEqual(new_to_auth, migration.to)
        self.assertEqual(State.review_follows, migration.state)
        self.assertEqual([], migration.followed)
        self.assertEqual([], migration.to_follow)
        self.assert_equals({'orig': 'data'}, migration.review)

        self.assert_task(mock_create_task, 'review', from_auth, new_to_auth)

    @patch('requests.get')
    def test_review_task_mastodon_to_bluesky(self, mock_get):
        alice = {
            'id': '234',
            'uri': 'http://in.st/users/alice',
            'username': 'alice',
            'display_name': 'Ms Alice',
            'acct': 'alice@in.st',
            'url': 'http://in.st/users/alice',
            'avatar': 'http://in.st/alice/pic',
        }
        bob = {
            'uri': 'http://bsky.brid.gy/ap/did:plc:bob',
            'username': 'bo.b',
            'acct': 'bo.b@bsky.brid.gy',
            'url': 'http://bsky.brid.gy/r/https://bsky.app/profile/bo.b',
            'avatar': 'http://bsky.app/bo.b/pic',
        }
        eve = {
            'uri': 'http://web.brid.gy/e.ve',
            'username': 'e.ve',
            'acct': 'e.ve@web.brid.gy',
            'url': 'http://e.ve/',
            'avatar': 'http://e.ve/pic',
        }

        mock_get.side_effect = [
            # followers
            requests_response([alice, bob], content_type='application/json'),
            # follows
            requests_response([alice, bob, eve], content_type='application/json'),
            # alice AP actor, webfinger
            requests_response(ALICE_AP_ACTOR, content_type=as2.CONTENT_TYPE),
            requests_response(ALICE_AP_ACTOR, content_type=as2.CONTENT_TYPE),
            requests_response(ALICE_WEBFINGER),
            requests_response(ALICE_WEBFINGER),
            # bob DID doc
            requests_response({
                # 'id': 'did:plc:alice',
                'alsoKnownAs': ['at://ba.wb'],
            }),
            # bob bsky profile
            requests_response(BOB_BSKY_PROFILE),
        ]

        self.make_bot_users()
        with ndb.context.Context(bridgy_fed_ndb).use():
            Web(id='e.ve', enabled_protocols=['atproto'],
                copies=[Target(protocol='atproto', uri='did:plc:eve')]).put()
            # allow to accounts bridged elsewhere, just not to from protocol
            Object(id='did:plc:alice', raw=DID_DOC).put()
            ATProto(id='did:plc:alice', enabled_protocols=['web']).put()

        with self.client.session_transaction() as sess:
            from_auth = self.make_mastodon(sess, login=False)
            to_auth = self.make_bluesky(sess, login=False)

        Migration.get_or_insert(from_auth.get(), to_auth.get())
        resp = self.post('/queue/review', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)

        self.assertEqual(('http://in.st/api/v1/accounts/234/followers?limit=80',),
                         mock_get.call_args_list[0].args)
        self.assertEqual(('http://in.st/api/v1/accounts/234/following?limit=80',),
                         mock_get.call_args_list[1].args)

        mock_get.reset_mock()
        resp = self.post('/queue/review', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(0, mock_get.call_count)

        migration = Migration.get_by_id('@alice@in.st atproto')
        self.assertEqual(from_auth, migration.from_)
        self.assertEqual(to_auth, migration.to)
        self.assertEqual(State.review_done, migration.state)
        self.assertEqual([], migration.followed)
        self.assertEqual(['did:plc:bob', 'did:plc:eve'], migration.to_follow)
        self.assert_equals(REVIEW_DATA_MASTODON_TO_BLUESKY, migration.review,
                           ignore=['follows_preview_raw', 'followers_preview_raw'])

    @patch('oauth_dropins.bluesky.oauth_client_for_pds',
           return_value=OAuth2Client(token_endpoint='https://un/used',
                                     client_id='unused', client_secret='unused'))
    @patch('requests.get')
    def test_review_task_bluesky_to_mastodon(self, mock_get, mock_oauth2client):
        alice = {
            '$type': 'app.bsky.actor.defs#profileView',
            'did': 'did:plc:alice',
            'handle': 'al.ice',
            'displayName': 'Ms Alice',
            'avatar': 'http://alice/pic',
        }
        bob = {
            '$type': 'app.bsky.actor.defs#profileView',
            'did': 'did:plc:bob',
            'handle': 'bo.b',
            'avatar': 'http://bob/pic',
        }
        eve = {
            '$type': 'app.bsky.actor.defs#profileView',
            'did': 'did:plc:eve',
            'handle': 'e.ve',
            'avatar': 'http://eve/pic',
        }
        mock_get.side_effect = [
            requests_response(DID_DOC),  # did:plc:alice
            requests_response({
                'subject': {'did': 'did:plc:alice', 'handle': 'al.ice'},
                'followers': [alice, bob],
            }),
            requests_response({
                'subject': {'did': 'did:plc:alice', 'handle': 'al.ice'},
                'follows': [alice, bob, eve],
            }),
        ]

        with ndb.context.Context(bridgy_fed_ndb).use():
            ATProto(id='did:plc:alice', enabled_protocols=['activitypub']).put()
            ActivityPub(id='http://in.st/users/alice').put()
            obj_key = Object(id='bob', as2={'preferredUsername': 'bawb'}).put()
            ActivityPub(id='http://inst/bob', obj_key=obj_key,
                        copies=[Target(protocol='atproto', uri='did:plc:bob')]).put()
            Web(id='e.ve', enabled_protocols=['atproto'],  # not activitypub
                copies=[Target(protocol='atproto', uri='did:plc:eve')]).put()

        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess, login=False)
            to_auth = self.make_mastodon(sess, login=False)

        Migration.get_or_insert(from_auth.get(), to_auth.get())
        resp = self.post('/queue/review', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)

        self.assertEqual(3, mock_get.call_count)
        self.assertEqual(
            ('https://api.bsky.app/xrpc/app.bsky.graph.getFollowers?actor=did%3Aplc%3Aalice&limit=100',),
            mock_get.call_args_list[1].args)
        self.assertEqual(
            ('https://api.bsky.app/xrpc/app.bsky.graph.getFollows?actor=did%3Aplc%3Aalice&limit=100',),
            mock_get.call_args_list[2].args)

        migration = Migration.get_by_id('did:plc:alice activitypub')
        self.assertEqual(from_auth, migration.from_)
        self.assertEqual(to_auth, migration.to)
        self.assertEqual(State.review_done, migration.state)
        self.assertEqual([], migration.followed)
        self.assertCountEqual(
            ['http://inst/bob', 'https://bsky.brid.gy/ap/did:plc:alice'],
            migration.to_follow)
        self.assert_equals(REVIEW_DATA_BLUESKY_TO_MASTODON, migration.review,
                           ignore=['follows_preview_raw', 'followers_preview_raw'])

    @patch('requests.post', side_effect=[
        requests_response({  # createSession
            'handle': 'han.dull',
            'did': 'did:plc:alice',
            'accessJwt': 'towkin',
            'refreshJwt': 'reephrush',
        }),
        requests_response({}),  # requestPlcOperationSignature
    ])
    def test_confirm_from_bluesky_request_plc_code(self, mock_post):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        resp = self.post('/confirm', from_auth, to_auth, password='hunter5')

        self.assertEqual(2, mock_post.call_count)
        self.assertEqual(
            ('https://some.pds/xrpc/com.atproto.server.createSession',),
            mock_post.call_args_list[0].args)
        self.assertEqual(
            {'identifier': 'did:plc:alice', 'password': 'hunter5'},
            mock_post.call_args_list[0].kwargs['json'])
        self.assertEqual(
            ('https://some.pds/xrpc/com.atproto.identity.requestPlcOperationSignature',),
            mock_post.call_args_list[1].args)
        self.assertEqual('towkin', from_auth.get().session['accessJwt'])

    @patch('requests.post', side_effect=[
        requests_response({  # createSession
            'error': 'AuthenticationRequired',
            'message': 'Invalid identifier or password',
        }, status=401),
    ])
    def test_confirm_from_bluesky_bad_password(self, mock_post):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        resp = self.post('/confirm', from_auth, to_auth, password='hunter5')

        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/bluesky-password?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}', resp.headers['Location'])
        flashed = get_flashed_messages()
        self.assertTrue(flashed[0].startswith('Login failed: '), flashed)

        self.assertEqual(1, mock_post.call_count)
        self.assertEqual(('https://some.pds/xrpc/com.atproto.server.createSession',),
                         mock_post.call_args_list[0].args)
        self.assertEqual({'identifier': 'did:plc:alice', 'password': 'hunter5'},
                         mock_post.call_args_list[0].kwargs['json'])
        self.assertIsNone(from_auth.get().session)

    def test_migrate_post_done(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        Migration.get_or_insert(from_auth.get(), to_auth.get(),
                                state=State.migrate_done)

        resp = self.post('/migrate', from_auth, to_auth)
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/migrate?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}', resp.headers['Location'])

    def test_migrate_get_done(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        Migration.get_or_insert(from_auth.get(), to_auth.get(),
                                state=State.migrate_done)

        resp = self.get('/migrate', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)
        self.assertNotIn('<meta http-equiv="refresh" content="5">',
                         resp.get_data(as_text=True))

    def test_migrate_no_from(self):
        with self.client.session_transaction() as sess:
            auth = self.make_mastodon(sess)

        resp = self.post('/migrate', to_key=auth)
        self.assertEqual(400, resp.status_code)

    def test_migrate_no_to(self):
        with self.client.session_transaction() as sess:
            auth = self.make_mastodon(sess)

        resp = self.post('/migrate', from_key=auth)
        self.assertEqual(400, resp.status_code)

    def test_migrate_not_logged_in(self):
        from_auth = MastodonAuth(id='@alice@in.st').key
        to_auth = BlueskyAuth(id='did:foo').key

        resp = self.post('/migrate', from_auth, to_auth)
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])

    def test_migrate_no_stored_migration(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_mastodon(sess)
            to_auth = self.make_bluesky(sess)

        resp = self.post('/migrate', from_auth, to_auth)
        self.assertEqual(404, resp.status_code)

    @patch.object(tasks_client, 'create_task')
    def test_migrate_starts_task(self, mock_create_task):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        migration = Migration.get_or_insert(from_auth.get(), to_auth.get(),
                                            state=State.review_done)

        resp = self.post('/migrate', from_auth, to_auth)
        self.assertEqual(302, resp.status_code)
        self.assertEqual(f'/migrate?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}', resp.headers['Location'])

        self.assert_task(mock_create_task, 'migrate', from_auth, to_auth)

        migration = migration.key.get()
        self.assertEqual(State.migrate_follows, migration.state)

    @patch.object(tasks_client, 'create_task')
    def test_migrate_with_stale_migration_starts_task(self, mock_create_task):
        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        yesterday = NOW - timedelta(days=1)
        with patch('bounce.Migration.updated._now', return_value=yesterday):
            migration = Migration.get_or_insert(from_auth.get(), to_auth.get(),
                                                state=State.migrate_out)

        self.assertEqual(yesterday, migration.key.get().updated)

        resp = self.post('/migrate', from_auth, to_auth)
        self.assertEqual(302, resp.status_code)

        self.assert_task(mock_create_task, 'migrate', from_auth, to_auth)
        self.assertGreater(migration.key.get().updated, yesterday)

    @patch.object(ActivityPub, 'migrate_in')  # TODO
    @patch.object(ATProto, 'migrate_out')     # TODO
    @patch('oauth_dropins.bluesky.oauth_client_for_pds',
           return_value=OAuth2Client(token_endpoint='https://un/used',
                                     client_id='unused', client_secret='unused'))
    @patch('requests.post', side_effect=[
        requests_response({
            'uri': 'at://did:plc:bob/fo.ll.ow/123',
            'cid': 'abcdefgh',
        }),
        requests_response({
            'uri': 'at://did:plc:eve/fo.ll.ow/456',
            'cid': 'xyzuvtsr',
        }),
        requests_response({}),  # create new did:plc
    ])
    @patch('requests.get', side_effect=[
        requests_response(DID_DOC),
        requests_response(ALICE_AP_ACTOR, content_type=as2.CONTENT_TYPE),
        requests_response(status=404),  # http://in.st/@alice/pic
    ])
    def test_migrate_task_mastodon_to_bluesky(self, mock_get, mock_post,
                                              mock_oauth2client, _, __):
        self.make_bot_users()

        with self.client.session_transaction() as sess:
            from_auth = self.make_mastodon(sess, login=False)
            to_auth = self.make_bluesky(sess, login=False)

        with ndb.context.Context(bridgy_fed_ndb).use():
            ActivityPub(id='http://in.st/users/alice').put()
            ATProto(id='did:plc:alice').put()

        migration = Migration(id='@alice@in.st atproto', from_=from_auth, to=to_auth,
                              to_follow=['did:bob', 'did:eve'],
                              state=State.migrate_follows,
                              ).put()

        resp = self.post('/queue/migrate', from_auth, to_auth)
        self.assertEqual(200, resp.status_code)
        self.assertEqual('OK', resp.get_data(as_text=True))

        mock_post.assert_has_calls([
            call('https://some.pds/xrpc/com.atproto.repo.createRecord', json={
                'repo': 'did:plc:alice',
                'collection': 'app.bsky.graph.follow',
                'record': {
                    '$type': 'app.bsky.graph.follow',
                    'subject': 'did:bob',
                    'createdAt': '2022-01-02T03:04:05.000Z',
                },
            }, data=None, headers=ANY, auth=ANY, timeout=60),
            call('https://some.pds/xrpc/com.atproto.repo.createRecord', json={
                'repo': 'did:plc:alice',
                'collection': 'app.bsky.graph.follow',
                'record': {
                    '$type': 'app.bsky.graph.follow',
                    'subject': 'did:eve',
                    'createdAt': '2022-01-02T03:04:05.000Z',
                },
            }, data=None, headers=ANY, auth=ANY, timeout=60),
        ], any_order=True)

        migration = migration.get()
        self.assertEqual(State.migrate_done, migration.state)
        self.assertEqual(['did:bob', 'did:eve'], migration.followed)
        self.assertEqual([], migration.to_follow)

    @patch.object(tasks_client, 'create_task')  # for atproto-commit task
    @patch('oauth_dropins.bluesky.oauth_client_for_pds',
           return_value=OAuth2Client(token_endpoint='https://un/used',
                                     client_id='unused', client_secret='unused'))
    @patch('requests.post', side_effect=[
        # createRecords for follows
        requests_response(status=400),
        requests_response({'id': '456', 'following': True}),
        requests_response({'operation': {'foo': 'bar'}}),  # signPlcOperation
        requests_response(),    # PLC update
        requests_response({}),  # deactivateAccount
    ])
    @patch('requests.get', side_effect=[
        requests_response(SNARFED2_DID_DOC),
        requests_response(ALICE_BSKY_PROFILE),
        requests_response(ALICE_AP_ACTOR, content_type=as2.CONTENT_TYPE),
        requests_response(ALICE_WEBFINGER),
        requests_response(ALICE_WEBFINGER),
        requests_response({'accounts': [{'id': '123', 'uri': 'http://other/bob'}]}),
        requests_response({'accounts': [{'id': '456', 'uri': 'http://other/eve'}]}),
        requests_response(SNARFED2_CAR, content_type='application/vnd.ipld.car'),
        requests_response(SNARFED2_DID_DOC),
        requests_response({
            **ALICE_AP_ACTOR,
            'alsoKnownAs': [f'https://bsky.brid.gy/ap/{SNARFED2_DID}'],
        }, content_type=as2.CONTENT_TYPE),
    ])
    def test_migrate_task_bluesky_to_mastodon(self, mock_get, mock_post,
                                              mock_oauth2client, mock_create_task):
        self.make_bot_users()

        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess, did=SNARFED2_DID, login=False)
            from_auth_entity = from_auth.get()
            from_auth_entity.session = {'accessJwt': 'towkin'}
            from_auth_entity.put()
            to_auth = self.make_mastodon(sess, login=False)

        migration = Migration.get_or_insert(
            from_auth_entity, to_auth.get(),
            to_follow=['http://other/bob', 'http://other/eve'],
            followed=['http://other/zed'], state=State.migrate_follows).put()

        resp = self.post('/queue/migrate', from_auth, to_auth, **{'plc-code': 'kowd'})
        self.assertEqual(200, resp.status_code)
        self.assertEqual('OK', resp.get_data(as_text=True))

        with ndb.context.Context(bridgy_fed_ndb).use():
            # check the repo import
            repo = server.storage.load_repo(SNARFED2_DID)
            self.assertIsNotNone(repo)
            self.assertEqual(SNARFED2_DID, repo.did)
            self.assertEqual(SNARFED2_RECORDS, repo.get_contents())

            # check the users
            ap_user = ActivityPub.get_by_id('http://in.st/users/alice')
            self.assertEqual(['atproto'], ap_user.enabled_protocols)
            self.assertEqual([Target(protocol='atproto', uri=SNARFED2_DID)],
                             ap_user.copies)
            profile_uri = f'at://{SNARFED2_DID}/app.bsky.actor.profile/self'
            self.assertEqual([Target(protocol='atproto', uri=profile_uri)],
                             ap_user.obj.copies)

            bsky_user = ATProto.get_by_id(SNARFED2_DID)
            self.assertEqual([], bsky_user.enabled_protocols)
            self.assertEqual([], bsky_user.copies)

        mock_get.assert_has_calls([
            call('http://in.st/api/v2/search', params={
                'resolve': True,
                'q': 'http://other/bob',
            }, headers=ANY, timeout=60, stream=True),
            call('http://in.st/api/v2/search', params={
                'resolve': True,
                'q': 'http://other/eve',
            }, headers=ANY, timeout=60, stream=True),
            call(f'https://some.pds/xrpc/com.atproto.sync.getRepo?did={quote(SNARFED2_DID)}',
                 json=None, data=None, headers=ANY),
        ], any_order=True)

        bsky_headers = {
            'Authorization': 'Bearer towkin',
            'User-Agent': 'Bridgy Fed (https://fed.brid.gy/)',
            'Content-Type': 'application/json',
        }
        mock_post.assert_has_calls([
            call('http://in.st/api/v1/accounts/123/follow',
                 headers=ANY, timeout=60, stream=True),
            call('http://in.st/api/v1/accounts/456/follow',
                 headers=ANY, timeout=60, stream=True),
            call('https://some.pds/xrpc/com.atproto.identity.signPlcOperation', json={
                'token': 'kowd',
                'rotationKeys': [did.encode_did_key(repo.rotation_key.public_key())],
                'verificationMethod': [{
                    'id': f'{SNARFED2_DID}#atproto',
                    'type': 'Multikey',
                    'controller': SNARFED2_DID,
                    'publicKeyMultibase': did.encode_did_key(repo.signing_key.public_key()),
                }],
                'services': {
                    'atproto_pds': {
                        'type': 'AtprotoPersonalDataServer',
                        'endpoint': 'https://atproto.brid.gy',
                    },
                },
            }, data=None, headers=bsky_headers),
            call(f'https://plc.directory/{SNARFED2_DID}', json={'foo': 'bar'},
                 timeout=15, stream=True, headers=ANY),
            call('https://some.pds/xrpc/com.atproto.server.deactivateAccount',
                 json=None, data=None, headers=bsky_headers),
        ], any_order=True)

        migration = migration.get()
        self.assertEqual(NOW, migration.last_attempt)
        self.assertEqual(['http://other/bob'], migration.to_follow)
        self.assertEqual(['http://other/zed', 'http://other/eve'], migration.followed)
