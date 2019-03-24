PORT = 8089

# If PORT and not default port
# BASEURL = "https://localhost:{}".format(PORT)
# BASEURL = "https://130.243.2.75:{}".format(PORT)
DOMAIN = '192.168.1.54'
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

PRIVATE_JWKS_PATH = "jwks_dir/jwks.json"
PUBLIC_JWKS_PATH = 'static/jwks.json'

SERVICES = ['WebFinger', 'ProviderInfoDiscovery', 'Registration',
            'Authorization', 'AccessToken', 'RefreshAccessToken', 'UserInfo',
            'EndSession']

# TESTTOOL_URL = 'https://rp.certification.openid.net:8080'
TESTTOOL_URL = 'https://192.168.1.109:5000'
TESTER_ID = 'oicrp'

TEMPLATE_DIR = 'templates'
