"""Unit tests for pages.py."""
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
