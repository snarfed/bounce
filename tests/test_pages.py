"""Unit tests for pages.py."""
import json
from unittest import TestCase
from unittest.mock import ANY, call, patch

from flask import get_flashed_messages, session
from google.cloud import ndb
from granary.source import html_to_text
from oauth_dropins.bluesky import BlueskyAuth
from oauth_dropins.mastodon import MastodonApp, MastodonAuth
from oauth_dropins.views import LOGINS_SESSION_KEY
from oauth_dropins.webutil import flask_util, testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.testutil import Asserts, requests_response, suppress_warnings
import requests

from app import app
import pages


class PagesTest(TestCase, Asserts):

    def setUp(self):
        super().setUp()
        suppress_warnings()

        self.client = app.test_client()
        self.client.__enter__()

        # clear datastore
        requests.post(f'http://{ndb_client.host}/reset')
        self.ndb_context = ndb_client.context()
        self.ndb_context.__enter__()

    def tearDown(self):
        self.ndb_context.__exit__(None, None, None)
        self.client.__exit__(None, None, None)
        super().tearDown()

    def test_front_page(self):
        # just check that we serve ok
        got = self.client.get('/')
        self.assert_equals(200, got.status_code)

    def test_logout(self):
        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [('BlueskyAuth', 'did:abc')]

        resp = self.client.post('/logout')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])
        self.assertNotIn(LOGINS_SESSION_KEY, session)

    def test_accounts_no_logins(self):
        resp = self.client.get('/accounts')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])

    def test_accounts(self):
        BlueskyAuth(id='did:plc:abc', user_json=json.dumps({
            'handle': 'abc.xyz',
            'avatar': 'http://abc/pic',
        })).put()
        MastodonAuth(id='@a@b.c', access_token_str='', user_json=json.dumps({
            'uri':'http://b.c/a',
            'avatar_static': 'http://b.c/pic',
        })).put()

        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [
                ('BlueskyAuth', 'did:plc:abc'),
                ('MastodonAuth', '@a@b.c'),
            ]

        resp = self.client.get('/accounts')
        self.assertEqual(200, resp.status_code)
        body = resp.get_data(as_text=True)

        # logins in header
        self.assert_multiline_in("""\
<a id="logins" href="/accounts">
<nobr title="Bluesky: abc.xyz">""", body, ignore_blanks=True)
        self.assert_multiline_in("""\
<nobr title="Mastodon: @a@b.c">""", body)

        # accounts
        self.assert_multiline_in("""\
<img src="http://abc/pic" class="profile">
<span style="unicode-bidi: isolate">abc.xyz</span>""", body)
        self.assert_multiline_in("""\
<img src="http://b.c/pic" class="profile">
<span style="unicode-bidi: isolate">@a@b.c</span>""", body)

    def test_review_no_auth_entity_param(self):
        resp = self.client.get('/review')
        self.assertEqual(400, resp.status_code)

    def test_review_not_logged_in(self):
        resp = self.client.get('/review?auth_entity=ahBicmlkZ3ktZmVkZXJhdGVkchcLEgxNYXN0b2RvbkF1dGgiBWFAYi5jDA')
        self.assertEqual(302, resp.status_code)
        self.assertEqual('/', resp.headers['Location'])

    @patch('requests.get')
    def test_review_mastodon(self, mock_get):
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
            'uri': 'http://web.brid.gy/ev.e',
            'username': 'ev.e',
            'acct': 'ev.e@web.brid.gy',
            'url': 'http://ev.e/',
            'avatar': 'http://ev.e/pic',
        }
        mock_get.side_effect = [
            # followers
            requests_response([alice, bob], content_type='application/json'),
            # follows
            requests_response([alice, bob, eve], content_type='application/json'),
        ]

        # # eve is native Bluesky, bridged into ActivityPub
        # with ndb.context.Context(pages.bridgy_fed_ndb).use():
        #     pages.ATProto(id='did:plc:eve', enabled_protocols=['activitypub']).put()
        #     pages.ATProto(id='did:plc:bob', enabled_protocols=['unknown']).put()

        app = MastodonApp(instance='https://in.st/', data='{}').put()
        auth = MastodonAuth(id='@alice@in.st', access_token_str='towkin', app=app,
                            user_json=json.dumps(alice)).put()

        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [('MastodonAuth', '@alice@in.st')]

        resp = self.client.get(f'/review?auth_entity={auth.urlsafe().decode()}')
        self.assertEqual(200, resp.status_code)

        # check Mastodon API calls
        self.assertEqual(2, mock_get.call_count)
        self.assertEqual(('https://in.st/api/v1/accounts/234/followers?limit=80',),
                         mock_get.call_args_list[0].args)
        self.assertEqual(('https://in.st/api/v1/accounts/234/following?limit=80',),
                         mock_get.call_args_list[1].args)

        # check rendered template
        body = resp.get_data(as_text=True)
        self.assert_multiline_in("""
document.getElementById('followers-chart'));
chart.draw(google.visualization.arrayToDataTable([['network', 'count'], ['activitypub', 1], ['atproto', 1]])""", body)
        self.assert_multiline_in("""
document.getElementById('follows-chart'));
chart.draw(google.visualization.arrayToDataTable([['network', 'count'], ['activitypub', 1], ['atproto', 1], ['web', 1]])""", body)

        text = html_to_text(body)
        self.assert_multiline_in("""
# Review
@alice@in.st
## Followers
* @alice@in.st · Ms Alice
* @bo.b@bsky.brid.gy
## Follows
* @alice@in.st · Ms Alice
* @bo.b@bsky.brid.gy
* @ev.e@web.brid.gy""", text, ignore_blanks=True)

    @patch('requests.get')
    def test_review_bluesky(self, mock_get):
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
            'handle': 'ev.e',
            'avatar': 'http://eve/pic',
        }
        mock_get.side_effect = [
            requests_response({
                'subject': {'did': 'did:plc:alice', 'handle': 'al.ice'},
                'followers': [alice, bob],
            }),
            requests_response({
                'subject': {'did': 'did:plc:alice', 'handle': 'al.ice'},
                'follows': [alice, bob, eve],
            }),
        ]

        # eve is native Bluesky, bridged into ActivityPub
        with ndb.context.Context(pages.bridgy_fed_ndb).use():
            pages.ATProto(id='did:plc:eve', enabled_protocols=['activitypub']).put()
            pages.ATProto(id='did:plc:bob', enabled_protocols=['unknown']).put()

        auth = BlueskyAuth(id='did:plc:alice', user_json=json.dumps(alice)).put()
        with self.client.session_transaction() as sess:
            sess[LOGINS_SESSION_KEY] = [('BlueskyAuth', 'did:plc:alice')]

        resp = self.client.get(f'/review?auth_entity={auth.urlsafe().decode()}')
        self.assertEqual(200, resp.status_code)

        # check Bluesky API calls
        self.assertEqual(2, mock_get.call_count)
        self.assertEqual(
            ('https://bsky.social/xrpc/app.bsky.graph.getFollowers?actor=did%3Aplc%3Aalice&limit=100',),
            mock_get.call_args_list[0].args)
        self.assertEqual(
            ('https://bsky.social/xrpc/app.bsky.graph.getFollows?actor=did%3Aplc%3Aalice&limit=100',),
            mock_get.call_args_list[1].args)

        # check rendered template
        body = resp.get_data(as_text=True)
#         self.assert_multiline_in("""
# document.getElementById('followers-chart'));
# chart.draw(google.visualization.arrayToDataTable([['network', 'count'], ['activitypub', 1], ['atproto', 1]])""", body)
#         self.assert_multiline_in("""
# document.getElementById('follows-chart'));
# chart.draw(google.visualization.arrayToDataTable([['network', 'count'], ['activitypub', 1], ['atproto', 1], ['web', 1]])""", body)
        self.assert_multiline_in("""
document.getElementById('follows-bridged-chart'));
chart.draw(google.visualization.arrayToDataTable([['type', 'count'], ['bridged', 1], ['not', 2]])""", body)

        text = html_to_text(body)
        self.assert_multiline_in("""
# Review
al.ice · did:plc:alice
## Followers
* al.ice · Ms Alice
* bo.b
## Follows
* al.ice · Ms Alice
* bo.b
* ev.e""", text, ignore_blanks=True)
