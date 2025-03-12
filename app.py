"""User-facing Flask app invoked by gunicorn in app.yaml.

Import all modules that define views in the app so that their URL routes get
registered.
"""
from flask_app import app

import pages
