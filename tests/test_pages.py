"""Unit tests for pages.py."""
import json

from flask import get_flashed_messages, session
from oauth_dropins.bluesky import BlueskyAuth
from oauth_dropins.mastodon import MastodonAuth
from oauth_dropins.views import LOGINS_SESSION_KEY
from oauth_dropins.webutil import flask_util, testutil, util
from oauth_dropins.webutil.appengine_config import ndb_client
from oauth_dropins.webutil.testutil import TestCase
from oauth_dropins.webutil.testutil import requests_response
import requests

from app import app


class PagesTest(TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.client.__enter__()

        # clear datastore
        requests.post(f'http://{ndb_client.host}/reset')
        self.ndb_context = ndb_client.context()
        self.ndb_context.__enter__()

        # self.app_context = app.app_context()
        # self.app_context.push()

    def tearDown(self):
        # self.app_context.pop()
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
