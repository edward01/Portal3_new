import os
_basedir = os.path.abspath(os.path.dirname(__file__))

db_config = {
    'test': dict(name='test', location=['127.0.0.1'], authenticate=False)
}

DEBUG = True
# SECRET_KEY = 'helloworld'

THREADS_PER_PAGE = 8

CSRF_ENABLED = True
CSRF_SESSION_KEY = 'session key'

RECAPTCHA_USE_SSL = False
RECAPTCHA_PUBLIC_KEY = ''
RECAPTCHA_PRIVATE_KEY = ''
RECAPTCHA_OPTIONS = {'theme': 'white'}