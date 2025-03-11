"""Flask config."""
import os
import re
import traceback

from oauth_dropins.webutil import appengine_config, appengine_info, util

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
# Not strict because we flash messages after cross-site redirects for OAuth,
# which strict blocks.
SESSION_COOKIE_SAMESITE = 'Lax'
CACHE_THRESHOLD = 3000

config_logger = logging.getLogger(__name__)

if appengine_info.DEBUG:
    ENV = 'development'
    CACHE_TYPE = 'NullCache'
    SECRET_KEY = 'sooper seekret'

else:
    ENV = 'production'
    CACHE_TYPE = 'SimpleCache'
    SECRET_KEY = util.read('flask_secret_key')

    logging.getLogger().setLevel(logging.INFO)
    if logging_client := getattr(appengine_config, 'logging_client'):
        logging_client.setup_logging(log_level=logging.INFO)

    logging.getLogger('lexrpc').setLevel(logging.DEBUG)

os.environ.setdefault('APPVIEW_HOST', 'api.bsky.local')
os.environ.setdefault('BGS_HOST', 'bgs.bsky.local')
os.environ.setdefault('PLC_HOST', 'plc.bsky.local')
os.environ.setdefault('REPO_TOKEN', util.read('repo_token'))
