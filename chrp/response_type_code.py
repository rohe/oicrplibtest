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
        "services": [
            ('WebFinger', {})
        ]
    },
    "rp-discovery-openid-configuration": {
        'issuer': '{}/{}/rp-discovery-openid-configuration'.format(TESTTOOL_URL,
                                                                   TESTER_ID),
        "services": [
            ('ProviderInfoDiscovery', {})
        ]
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
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {})]
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
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-userinfo-bearer-body': {
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
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {}),
            ('UserInfo', {})
        ]
    },
    'rp-scope-userinfo-claims': {
        'issuer': '{}/{}/rp-scope-userinfo-claims'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-scope-userinfo-claims".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {}),
            ('UserInfo', {})
        ]
    },
    'rp-nonce-invalid': {
        'issuer': '{}/{}/rp-nonce-invalid'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-nonce-invalid".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-kid-absent-single-jwks': {
        'issuer': '{}/{}/rp-id_token-kid-absent-single-jwks'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-kid-absent-single-jwks".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-iat': {
        'issuer': '{}/{}/rp-id_token-iat'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-iat".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-aud': {
        'issuer': '{}/{}/rp-id_token-aud'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-aud".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-kid-absent-multiple-jwks': {
        'issuer': '{}/{}/rp-id_token-kid-absent-multiple-jwks'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-kid-absent-multiple-jwks".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-sig-none': {
        'issuer': '{}/{}/rp-id_token-sig-none'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-sig-none".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-sig-rs256': {
        'issuer': '{}/{}/rp-id_token-sig-rs256'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-sig-rs256".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-sub': {
        'issuer': '{}/{}/rp-id_token-sub'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-sub".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-bad-sig-rs256': {
        'issuer': '{}/{}/rp-id_token-bad-sig-rs256'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-bad-sig-rs256".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-id_token-issuer-mismatch': {
        'issuer': '{}/{}/rp-id_token-issuer-mismatch'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-issuer-mismatch".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {})
        ]
    },
    'rp-userinfo-bad-sub-claim': {
        'issuer': '{}/{}/rp-userinfo-bad-sub-claim'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-userinfo-bad-sub-claim".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {}),
            ('UserInfo', {})
        ]
    },
    'rp-userinfo-bearer-header': {
        'issuer': '{}/{}/rp-userinfo-bearer-header'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-userinfo-bearer-header".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
            ('Authorization', {}),
            ('AccessToken', {}),
            ('UserInfo', {'default_authn_method': 'bearer_header'})
        ]
    },
    'rp-discovery-webfinger-acct': {
        'resource': '{}.rp-discovery-webfinger-acct@{}'.format(TESTER_ID,
                                                               TESTTOOL_URL),
        "services": [
            ('WebFinger', {})
        ]
    },
    'rp-discovery-webfinger-http-href': {
        'resource': '{}/{}/rp-discovery-webfinger-http-href'.format(
            TESTTOOL_URL, TESTER_ID),
        "services": [
            ('WebFinger', {})
        ]
    },
    'rp-discovery-jwks_uri-keys': {
        'issuer': '{}/{}/rp-discovery-openid-configuration'.format(TESTTOOL_URL,
                                                                   TESTER_ID),
        "services": [
            ('ProviderInfoDiscovery', {})
        ]
    },
    'rp-discovery-issuer-not-matching-config': {
        'issuer': '{}/{}/rp-discovery-issuer-not-matching-config'.format(
            TESTTOOL_URL, TESTER_ID),
        "services": [
            ('ProviderInfoDiscovery', {})
        ]
    },
    'rp-discovery-webfinger-unknown-member': {
        'resource': '{}/{}/rp-discovery-webfinger-unknown-member'.format(
            TESTTOOL_URL, TESTER_ID),
        "services": [
            ('WebFinger', {})
        ]
    },
    'rp-registration-dynamic': {
        'issuer': '{}/{}/rp-registration-dynamic'.format(TESTTOOL_URL,
                                                         TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-registration-dynamic".format(BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": [
            ('ProviderInfoDiscovery', {}),
            ('Registration', {}),
        ]
    },
    'rp-request_uri-enc': {},
    'rp-request_uri-sig': {},
    'rp-request_uri-sig+enc': {},
    'rp-request_uri-unsigned': {},
    'rp-token_endpoint-private_key_jwt': {},
    'rp-token_endpoint-client_secret_post': {},
    'rp-token_endpoint-client_secret_jwt': {},
    'rp-id_token-sig+enc': {},
    'rp-id_token-sig-hs256': {},
    'rp-id_token-sig-es256': {},
    'rp-id_token-sig+enc-a128kw': {},
    'rp-id_token-bad-sig-hs256': {},
    'rp-id_token-bad-sig-es256': {},
    'rp-key-rotation-op-sign-key-native': {},
    'rp-key-rotation-op-sign-key': {},
    'rp-key-rotation-op-enc-key': {},
    'rp-claims-distributed': {},
    'rp-claims-aggregated': {},
    'rp-userinfo-sig': {},
    'rp-userinfo-enc': {},
    'rp-userinfo-sig+enc': {},
    'rp-3rd_party-init-login': {}
}