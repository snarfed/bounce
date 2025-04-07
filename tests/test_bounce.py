"""Unit tests for bounce.py."""
import json
from unittest import TestCase
from unittest.mock import ANY, call, patch

from arroba import did
from Crypto.PublicKey import RSA
from flask import get_flashed_messages, session
from google.cloud import ndb
from granary.source import html_to_text
import granary.mastodon
from oauth_dropins.bluesky import BlueskyAuth
from oauth_dropins.mastodon import MastodonApp, MastodonAuth
from oauth_dropins.views import LOGINS_SESSION_KEY
from oauth_dropins.webutil import flask_util, testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
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
from common import long_to_base64
import ids
from models import Target
import protocol
from web import Web

from bounce import app, bridgy_fed_ndb, Migration

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
        protocol.Protocol.for_id.cache.clear()
        protocol.Protocol.for_handle.cache.clear()

        util.now = lambda **kwargs: NOW

    def tearDown(self):
        self.ndb_context.__exit__(None, None, None)
        self.client.__exit__(None, None, None)
        super().tearDown()

    def make_mastodon(self, sess):
        app = MastodonApp(instance='https://in.st/', data='{}').put()
        user_json = json.dumps({
            'id': '234',
            'uri':'http://in.st/@alice',
            'avatar_static': 'http://in.st/@alice/pic',
        })
        auth = MastodonAuth(id='@alice@in.st', access_token_str='towkin', app=app,
                            user_json=user_json).put()

        sess.setdefault(LOGINS_SESSION_KEY, []).append(
            ('MastodonAuth', '@alice@in.st'))

        return auth

    def make_bluesky(self, sess):
        user_json = json.dumps({
            '$type': 'app.bsky.actor.defs#profileView',
            'handle': 'al.ice',
            'avatar': 'http://alice/pic',
        })
        auth = BlueskyAuth(id='did:plc:alice', pds_url='http://some.pds/',
                           user_json=user_json, dpop_token=DPOP_TOKEN_STR).put()

        sess.setdefault(LOGINS_SESSION_KEY, []).append(
            ('BlueskyAuth', 'did:plc:alice'))

        return auth

    def test_front_page(self):
        got = self.client.get('/')
        self.assert_equals(200, got.status_code)

    def test_logout(self):
        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [('BlueskyAuth', 'did:abc')]

        resp = self.client.post('/logout')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])
        self.assertNotIn(LOGINS_SESSION_KEY, session)

    def test_from_no_logins(self):
        resp = self.client.get('/from')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])

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
        self.assert_multiline_in("""\
<nobr title="Mastodon: @alice@in.st">""", body)

        self.assert_multiline_in("""\
<a class="actor" href="/to?from=agNhcHByHgsSC0JsdWVza3lBdXRoIg1kaWQ6cGxjOmFsaWNlDA">
<img src="/oauth_dropins_static/bluesky_icon.png"
class="logo" title="Bluesky" />
<img src="http://alice/pic" class="profile">
<span style="unicode-bidi: isolate">al.ice</span>""", body)
        self.assert_multiline_in("""\
<img src="http://in.st/@alice/pic" class="profile">
<span style="unicode-bidi: isolate">@alice@in.st</span>""", body)

    def test_review_no_auth_param(self):
        resp = self.client.get('/review')
        self.assertEqual(400, resp.status_code)

    def test_review_not_logged_in(self):
        resp = self.client.get('/review?from=ahBicmlkZ3ktZmVkZXJhdGVkchcLEgxNYXN0b2RvbkF1dGgiBWFAYi5jDA&to=ahBicmlkZ3ktZmVkZXJhdGVkchcLEgxNYXN0b2RvbkF1dGgiBWFAYi5jDA')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])

    @patch('oauth_dropins.bluesky.oauth_client_for_pds',
           return_value=OAuth2Client(token_endpoint='https://un/used',
                                     client_id='unused', client_secret='unused'))
    @patch('requests.get')
    def test_review_mastodon(self, mock_get, mock_oauth2client):
        alice = {
            'id': '234',
            'uri': 'http://in.st/users/alice',
            'username': 'alice',
            'display_name': 'Ms Alice',
            'acct': 'alice@in.st',
            'url': 'http://in.st/@alice',
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
        ]

        with ndb.context.Context(bridgy_fed_ndb).use():
            Web(id='e.ve', enabled_protocols=['atproto']).put()

        with self.client.session_transaction() as sess:
            from_auth = self.make_mastodon(sess)
            to_auth = self.make_bluesky(sess)

        resp = self.client.get(f'/review?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}')
        self.assertEqual(200, resp.status_code)

        self.assertEqual(2, mock_get.call_count)
        self.assertEqual(('https://in.st/api/v1/accounts/234/followers?limit=80',),
                         mock_get.call_args_list[0].args)
        self.assertEqual(('https://in.st/api/v1/accounts/234/following?limit=80',),
                         mock_get.call_args_list[1].args)

        body = resp.get_data(as_text=True)
        self.assert_multiline_in("""
document.getElementById('followers-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 1]])""", body)
        self.assert_multiline_in("""
document.getElementById('follows-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 0], ["Web", 1], ["not bridged", 1]])""", body)

        text = html_to_text(body)
        self.assert_multiline_in("""
When you migrate  @alice@in.st to  al.ice ...
### You'll keep _all_ of your followers.
* @alice@in.st · Ms Alice
* @bo.b@bsky.brid.gy
### You'll keep _67%_ of your follows.
* @alice@in.st · Ms Alice
* @bo.b@bsky.brid.gy
* @e.ve@web.brid.gy""", text, ignore_blanks=True)

        mock_get.reset_mock()
        resp = self.client.get(f'/review?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual(0, mock_get.call_count)

    @patch('oauth_dropins.bluesky.oauth_client_for_pds',
           return_value=OAuth2Client(token_endpoint='https://un/used',
                                     client_id='unused', client_secret='unused'))
    @patch('requests.get')
    def test_review_bluesky(self, mock_get, mock_oauth2client):
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
            requests_response({}),  # did:plc:alice
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
            ActivityPub(id='http://inst/bob',
                        copies=[Target(protocol='atproto', uri='did:plc:bob')]).put()
            Web(id='e.ve', enabled_protocols=['atproto'],  # not activitypub
                copies=[Target(protocol='atproto', uri='did:plc:eve')]).put()

        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        resp = self.client.get(f'/review?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}')
        self.assertEqual(200, resp.status_code)

        self.assertEqual(3, mock_get.call_count)
        self.assertEqual(
            ('http://some.pds/xrpc/app.bsky.graph.getFollowers?actor=did%3Aplc%3Aalice&limit=100',),
            mock_get.call_args_list[1].args)
        self.assertEqual(
            ('http://some.pds/xrpc/app.bsky.graph.getFollows?actor=did%3Aplc%3Aalice&limit=100',),
            mock_get.call_args_list[2].args)

        body = resp.get_data(as_text=True)
        self.assert_multiline_in("""
document.getElementById('followers-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 1], ["Web", 0]])""", body)
        self.assert_multiline_in("""
document.getElementById('follows-chart'));
chart.draw(google.visualization.arrayToDataTable([["type", "count"], ["ATProto", 1], ["ActivityPub", 1], ["Web", 0], ["not bridged", 1]])""", body)

        text = html_to_text(body)
        self.assert_multiline_in("""
When you migrate  al.ice to  @alice@in.st ...
### You'll keep _all_ of your followers.
* al.ice · Ms Alice
* bo.b
### You'll keep _67%_ of your follows.
* al.ice · Ms Alice
* bo.b
* e.ve""", text, ignore_blanks=True)

    def test_migrate_no_from_auth(self):
        with self.client.session_transaction() as sess:
            auth = self.make_mastodon(sess)

        for fn in (self.client.get, self.client.post):
            resp = self.client.post(f'/migrate?to={auth.urlsafe().decode()}')
            self.assertEqual(400, resp.status_code)

    def test_migrate_no_to(self):
        with self.client.session_transaction() as sess:
            auth = self.make_mastodon(sess)

        for fn in (self.client.get, self.client.post):
            resp = self.client.post(f'/migrate?from={auth.urlsafe().decode()}')
            self.assertEqual(400, resp.status_code)

    def test_migrate_not_logged_in(self):
        from_auth = MastodonAuth(id='@alice@in.st').key.urlsafe().decode()
        to_auth = BlueskyAuth(id='did:foo').key.urlsafe().decode()

        for fn in (self.client.get, self.client.post):
            resp = self.client.post(f'/migrate?from={from_auth}&to={to_auth}')
            self.assertEqual(302, resp.status_code)
            self.assertEqual('/', resp.headers['Location'])

    def test_migrate_no_migration(self):
        with self.client.session_transaction() as sess:
            from_auth = self.make_mastodon(sess)
            to_auth = self.make_bluesky(sess)

        resp = self.client.post(f'/migrate?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}')
        self.assertEqual(404, resp.status_code)

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
    ])
    def test_migrate_success(self, mock_post, mock_oauth2client):
        with self.client.session_transaction() as sess:
            from_auth = self.make_mastodon(sess)
            to_auth = self.make_bluesky(sess)

        with ndb.context.Context(bridgy_fed_ndb).use():
            ActivityPub(id='http://in.st/@alice').put()
            ATProto(id='did:plc:alice').put()

        migration = Migration(id=from_auth.id(), to=to_auth,
                              to_follow=['did:bob', 'did:eve'],
                              ).put()

        resp = self.client.post(f'/migrate?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('ok', resp.get_data(as_text=True))

        mock_post.assert_has_calls([
            call('http://some.pds/xrpc/com.atproto.repo.createRecord', json={
                'repo': 'did:plc:alice',
                'collection': 'app.bsky.graph.follow',
                'record': {
                    '$type': 'app.bsky.graph.follow',
                    'subject': 'did:bob',
                    'createdAt': '2022-01-02T03:04:05.000Z',
                },
            }, data=None, headers=ANY, auth=ANY),
            call('http://some.pds/xrpc/com.atproto.repo.createRecord', json={
                'repo': 'did:plc:alice',
                'collection': 'app.bsky.graph.follow',
                'record': {
                    '$type': 'app.bsky.graph.follow',
                    'subject': 'did:eve',
                    'createdAt': '2022-01-02T03:04:05.000Z',
                },
            }, data=None, headers=ANY, auth=ANY),
        ], any_order=True)

        migration = migration.get()
        self.assertEqual(NOW, migration.last_attempt)
        self.assertEqual(['did:bob', 'did:eve'], migration.followed)
        self.assertEqual([], migration.to_follow)

    @patch('oauth_dropins.bluesky.oauth_client_for_pds',
           return_value=OAuth2Client(token_endpoint='https://un/used',
                                     client_id='unused', client_secret='unused'))
    @patch('requests.post', side_effect=[
        requests_response(status=400),
        requests_response({'id': '456', 'following': True}),
    ])
    @patch('requests.get', side_effect=[
        requests_response(DID_DOC),
        # Bluesky profile
        requests_response({
            'uri': 'at://did:plc:alice/app.bsky.actor.profile/self',
            'cid': 'abcdefgh',
            'record': {'displayName': 'Alice'},
        }),
        requests_response({'id': 'http://other/bob'}),
        requests_response({'accounts': [{'id': '123', 'uri': 'http://other/bob'}]}),
        requests_response({'accounts': [{'id': '456', 'uri': 'http://other/eve'}]}),
    ])
    def test_migrate_partial_success(self, mock_get, mock_post, mock_oauth2client):
        key = RSA.generate(1024)
        with ndb.context.Context(bridgy_fed_ndb).use():
            Web(id='fed.brid.gy', mod=long_to_base64(key.n),
                public_exponent=long_to_base64(key.e),
                private_exponent=long_to_base64(key.d)).put()

        with self.client.session_transaction() as sess:
            from_auth = self.make_bluesky(sess)
            to_auth = self.make_mastodon(sess)

        migration = Migration(id=from_auth.id(), to=to_auth,
                              to_follow=['http://other/bob', 'http://other/eve'],
                              followed=['http://other/zed'],
                              ).put()

        resp = self.client.post(f'/migrate?from={from_auth.urlsafe().decode()}&to={to_auth.urlsafe().decode()}')
        self.assertEqual(200, resp.status_code)
        self.assertEqual('ok', resp.get_data(as_text=True))

        mock_get.assert_has_calls([
            call('https://in.st/api/v2/search', params={
                'resolve': True,
                'q': 'http://other/bob',
            }, headers=ANY, timeout=15, stream=True),
            call('https://in.st/api/v2/search', params={
                'resolve': True,
                'q': 'http://other/eve',
            }, headers=ANY, timeout=15, stream=True),
        ])
        mock_post.assert_has_calls([
            call('https://in.st/api/v1/accounts/123/follow',
                 headers=ANY, timeout=15, stream=True),
            call('https://in.st/api/v1/accounts/456/follow',
                 headers=ANY, timeout=15, stream=True),
        ], any_order=True)

        migration = migration.get()
        self.assertEqual(NOW, migration.last_attempt)
        self.assertEqual(['http://other/bob'], migration.to_follow)
        self.assertEqual(['http://other/zed', 'http://other/eve'], migration.followed)
