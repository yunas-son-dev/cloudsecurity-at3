"""Elastic Beanstalk entry point.

Elastic Beanstalk (and our Procfile) look for a WSGI callable called
`application` in this module. Locally: `flask --app application run`.

Debug mode is never switched on here. Do not add `debug=True` anywhere.
"""
from app import create_app

application = create_app()
