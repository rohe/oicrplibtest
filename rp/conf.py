PORT = 8100

# If PORT and not default port
# BASEURL = "https://localhost:{}".format(PORT)
# BASEURL = "https://130.243.2.75:{}".format(PORT)
DOMAIN = '127.0.0.1'
BASEURL = "https://{}:{}".format(DOMAIN, PORT)

# else
# BASEURL = "https://localhost"

# If BASE is https these has to be specified
SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CA_BUNDLE = None

VERIFY_SSL = False

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

RP_KEYS = {
    'private_path': 'private/jwks.json',
    'key_defs': KEYDEFS,
    'public_path': 'static/jwks.json',
    # this will create the jwks files if they are absent
    'read_only': False
}

SERVICES = {
    'webfinger': {
        'class': 'oidcservice.oidc.webfinger.WebFinger',
        'kwargs': {}
    },
    'discovery': {
        'class': 'oidcservice.oidc.provider_info_discovery.ProviderInfoDiscovery',
        'kwargs': {}
    },
    'registration': {
        'class': 'oidcservice.oidc.registration.Registration',
        'kwargs': {}
    },
    'authorization': {
        'class': 'oidcservice.oidc.authorization.Authorization',
        'kwargs': {}
    },
    'access_token': {
        'class': 'oidcservice.oidc.access_token.AccessToken',
        'kwargs': {}
    },
    'refresh_access_token': {
        'class': 'oidcservice.oidc.refresh_access_token.RefreshAccessToken',
        'kwargs': {}
    },
    'userinfo': {
        'class': 'oidcservice.oidc.userinfo.UserInfo',
        'kwargs': {}
    },
    'end_session': {
        'class': 'oidcservice.oidc.end_session.EndSession',
        'kwargs': {}
    }
}

# TESTTOOL_URL = 'https://rp.certification.openid.net:8080'
# TESTTOOL_URL = 'https://192.168.1.54:8080'
TESTTOOL_URL = 'https://127.0.0.1:8080'
TESTER_ID = 'oidcrp'

TEMPLATE_DIR = 'templates'
