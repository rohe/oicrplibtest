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

SERVICES = ['webFinger', 'ProviderInfoDiscovery', 'Registration',
            'Authorization', 'AccessToken', 'RefreshAccessToken', 'UserInfo']

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
        "services": {
            'WebFinger': {}
        }
    },
    "rp-discovery-openid-configuration": {
        'issuer': '{}/{}/rp-discovery-openid-configuration'.format(TESTTOOL_URL,
                                                                   TESTER_ID),
        "services": {
            'ProviderInfoDiscovery': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {}}
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {'verify': {'allow_missing_kid': True}}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-id_token-aud': {
        'issuer': '{}/{}/rp-id_token-aud'.format(TESTTOOL_URL, TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-aud".format(BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {'verify': {'allow_missing_kid': True}}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {'default_authn_method': 'bearer_header'}
        }
    },
    'rp-discovery-webfinger-acct': {
        'resource': 'acct:{}.rp-discovery-webfinger-acct@localhost:8080'.format(
            TESTER_ID),
        "services": {
            'WebFinger': {}
        }
    },
    'rp-discovery-webfinger-http-href': {
        'resource': '{}/{}/rp-discovery-webfinger-http-href'.format(
            TESTTOOL_URL, TESTER_ID),
        "services": {
            'WebFinger': {}
        }
    },
    'rp-discovery-jwks_uri-keys': {
        'issuer': '{}/{}/rp-discovery-openid-configuration'.format(TESTTOOL_URL,
                                                                   TESTER_ID),
        "services": {
            'ProviderInfoDiscovery': {'pre_load_keys': True}
        }
    },
    'rp-discovery-issuer-not-matching-config': {
        'issuer': '{}/{}/rp-discovery-issuer-not-matching-config'.format(
            TESTTOOL_URL, TESTER_ID),
        "services": {
            'ProviderInfoDiscovery': {}
        }
    },
    'rp-discovery-webfinger-unknown-member': {
        'resource': '{}/{}/rp-discovery-webfinger-unknown-member'.format(
            TESTTOOL_URL, TESTER_ID),
        "services": {
            'WebFinger': {}
        }
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
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
        }
    },
    'rp-request_uri-enc': {
        'issuer': '{}/{}/rp-request_uri-enc'.format(TESTTOOL_URL,
                                                    TESTER_ID),
        "redirect_uris": ["{}/authz_cb/rp-request_uri-enc".format(BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
        'behaviour': {'jwks_uri': '{}/{}'. format(BASEURL, PUBLIC_JWKS_PATH)},
        'requests_dir': 'static',
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {
                'pre_construct': {'request_method': 'request_uri'},
                'post_construct': {
                    'request_method': 'request_uri',
                    'request_object_signing_alg': 'none',
                    'request_object_encryption_alg': '',
                    'request_object_encryption_enc': '',
                    'target': '{}/{}/rp-request_uri-enc'.format(TESTTOOL_URL,
                                                                TESTER_ID)
                }
            }
        }
    },
    'rp-request_uri-sig': {
        'issuer': '{}/{}/rp-request_uri-sig'.format(TESTTOOL_URL,
                                                    TESTER_ID),
        "redirect_uris": ["{}/authz_cb/rp-request_uri-sig".format(BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
        'behaviour': {'jwks_uri': '{}/{}'. format(BASEURL, PUBLIC_JWKS_PATH)},
        'requests_dir': 'static',
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {
                'pre_construct': {'request_method': 'request_uri'},
                'post_construct': {
                    'request_method': 'request_uri',
                    'request_object_signing_alg': 'RS256'}
            }
        }
    },
    'rp-request_uri-sig+enc': {
        'issuer': '{}/{}/rp-request_uri-sig+enc'.format(TESTTOOL_URL,
                                                        TESTER_ID),
        "redirect_uris": ["{}/authz_cb/rp-request_uri-sig+enc".format(BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
        'behaviour': {'jwks_uri': '{}/{}'. format(BASEURL, PUBLIC_JWKS_PATH)},
        'requests_dir': 'static',
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {
                'pre_construct': {'request_method': 'request_uri'},
                'post_construct': {
                    'request_method': 'request_uri',
                    'request_object_signing_alg': 'RS256',
                    'request_object_encryption_alg': '',
                    'request_object_encryption_enc': '',
                    'target': '{}/{}/rp-request_uri-enc'.format(TESTTOOL_URL,
                                                                TESTER_ID)
                }
            }
        }
    },
    'rp-request_uri-unsigned': {
        'issuer': '{}/{}/rp-request_uri-unsigned'.format(TESTTOOL_URL,
                                                         TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-request_uri-unsigned".format(BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post'],
        },
        'requests_dir': 'static',
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {
                'pre_construct': {'request_method': 'request_uri'},
                'post_construct': {
                    'request_method': 'request_uri',
                    'request_object_signing_alg': 'none',
                }
            }
        }
    },
    'rp-token_endpoint-private_key_jwt': {
        'issuer': '{}/{}/rp-token_endpoint-private_key_jwt'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-token_endpoint-private_key_jwt".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["private_key_jwt"],
        },
        'behaviour': {'jwks_uri': '{}/{}'. format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-token_endpoint-client_secret_post': {
        'issuer': '{}/{}/rp-token_endpoint-client_secret_post'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-token_endpoint-client_secret_post".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_post"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-token_endpoint-client_secret_jwt': {
        'issuer': '{}/{}/rp-token_endpoint-client_secret_jwt'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-token_endpoint-client_secret_jwt".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_jwt"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-id_token-sig+enc': {
        'issuer': '{}/{}/rp-id_token-sig+enc'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-sig+enc".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-id_token-sig-hs256': {
        'issuer': '{}/{}/rp-id_token-sig-hs256'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-sig-hs256".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-id_token-sig-es256': {
        'issuer': '{}/{}/rp-id_token-sig-es256'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-sig-es256".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-id_token-sig+enc-a128kw': {
        'issuer': '{}/{}/rp-id_token-sig+enc-a128kw'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-sig+enc-a128kw".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-id_token-bad-sig-hs256': {
        'issuer': '{}/{}/rp-id_token-bad-sig-hs256'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-bad-sig-hs256".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-id_token-bad-sig-es256': {
        'issuer': '{}/{}/rp-id_token-bad-sig-es256'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-id_token-bad-sig-es256".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        'behaviour': {'jwks_uri': '{}/{}'.format(BASEURL, PUBLIC_JWKS_PATH)},
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {}
        }
    },
    'rp-key-rotation-op-sign-key-native': {},
    'rp-key-rotation-op-sign-key': {},
    'rp-key-rotation-op-enc-key': {},
    'rp-claims-distributed': {},
    'rp-claims-aggregated': {},
    'rp-userinfo-sig': {
        'issuer': '{}/{}/rp-userinfo-sig'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-userinfo-sig".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
    },
    'rp-userinfo-enc': {
        'issuer': '{}/{}/rp-userinfo-enc'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-userinfo-enc".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
    },
    'rp-userinfo-sig+enc': {
        'issuer': '{}/{}/rp-userinfo-sig+enc'.format(
            TESTTOOL_URL,
            TESTER_ID),
        "redirect_uris": [
            "{}/authz_cb/rp-userinfo-sig+enc".format(
                BASEURL)],
        "client_prefs": {
            "application_type": "web",
            "application_name": "rphandler",
            "contacts": ["ops@example.com"],
            "response_types": ["code"],
            "scope": ["openid", "profile", "email", "address", "phone"],
            "token_endpoint_auth_method": ["client_secret_basic"],
        },
        "services": {
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
    },
    'rp-3rd_party-init-login': {}
}
