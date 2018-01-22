# BASE = "https://lingon.ladok.umu.se"

PORT = 8089

# If PORT and not default port
BASEURL = "https://localhost:{}".format(PORT)
# else
# BASEURL = "https://localhost"

# If BASE is https these has to be specified
SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CA_BUNDLE = None

VERIFY_SSL = False

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

PRIVATE_JWKS_PATH = "jwks_dir/jwks.json"
PUBLIC_JWKS_PATH = 'static/jwks.json'
# information used when registering the client, this may be the same for all OPs

SERVICES = ['ProviderInfoDiscovery', 'Registration', 'Authorization',
            'AccessToken', 'RefreshAccessToken', 'UserInfo']

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": ["client_secret_basic", 'client_secret_post'],
}

# The keys in this dictionary are the OPs short user friendly name
# not the issuer (iss) name.

TESTTOOL_URL = 'https://localhost:8080'
TESTER_ID = 'oicrp'

CLIENTS = {
    # Supports OP information lookup but not client registration
    "rp-discovery-webfinger-url": {
        'resource': '{}/{}/rp-discovery-webfinger-url'.format(TESTTOOL_URL,
                                                              TESTER_ID),
        "services": ['WebFinger']
    },
    "rp-discovery-openid-configuration": {
        'issuer': '{}/{}/rp-discovery-openid-configuration'.format(TESTTOOL_URL,
                                                                   TESTER_ID),
        "services": ['ProviderInfoDiscovery']
    },
    'rp-response_type-code': {
        'issuer': '{}/{}/rp-response_type-code'.format(TESTTOOL_URL,
                                                       TESTER_ID),
        "redirect_uris": ["{}/authz_cb/rp-response_type-code".format(BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
        "services": ['ProviderInfoDiscovery', 'Registration', 'Authorization']
    },
    'rp-token_endpoint-client_secret_basic': {
        'issuer': '{}/{}/rp-token_endpoint-client_secret_basic'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-token_endpoint-client_secret_basic".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": ['ProviderInfoDiscovery', 'Registration', 'Authorization',
                     'AccessToken']
    },
    'rp-userinfo-bearer-body':{
        'issuer': '{}/{}/rp-userinfo-bearer-body'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-userinfo-bearer-body".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": ['ProviderInfoDiscovery', 'Registration', 'Authorization',
                     'AccessToken', 'UserInfo']
    }
}
