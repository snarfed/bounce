"""Flask app."""
from pathlib import Path
import sys

from flask import Flask
import flask_gae_static
from oauth_dropins.webutil import (
    appengine_info,
    appengine_config,
    flask_util,
)


app_dir = Path(__file__).parent

app = Flask(__name__, static_folder=None)
app.template_folder = './templates'
app.json.compact = False
app.config.from_pyfile(app_dir / 'config.py')
app.url_map.converters['regex'] = flask_util.RegexConverter
app.after_request(flask_util.default_modern_headers)
app.register_error_handler(Exception, flask_util.handle_exception)

if (appengine_info.LOCAL_SERVER
    # ugly hack to infer if we're running unit tests
    and 'unittest' not in sys.modules):
    flask_gae_static.init_app(app)

app.wsgi_app = flask_util.ndb_context_middleware(
    app.wsgi_app, client=appengine_config.ndb_client)
