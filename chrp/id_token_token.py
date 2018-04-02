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
    "rp-3rd_party-init-login":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-3rd_party-init-login".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-claims-aggregated":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-claims-aggregated".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-claims-distributed":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-claims-distributed".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-claims_request-id_token":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-claims_request-id_token".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-claims_request-userinfo":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-claims_request-userinfo".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-discovery-issuer-not-matching-config":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-discovery-issuer-not-matching-config".format(
                    BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-discovery-jwks_uri-keys":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-discovery-jwks_uri-keys".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-discovery-openid-configuration":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-discovery-openid-configuration".format(
                    BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-discovery-webfinger-acct":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-discovery-webfinger-acct".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-discovery-webfinger-http-href":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-discovery-webfinger-http-href".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-discovery-webfinger-unknown-member":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-discovery-webfinger-unknown-member".format(
                    BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-discovery-webfinger-url":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-discovery-webfinger-url".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-aud":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-aud".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-bad-at_hash":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-bad-at_hash".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-bad-sig-es256":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-bad-sig-es256".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-bad-sig-hs256":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-bad-sig-hs256".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-bad-sig-rs256":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-bad-sig-rs256".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-iat":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-iat".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-issuer-mismatch":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-issuer-mismatch".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-kid-absent-multiple-jwks":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-kid-absent-multiple-jwks".format(
                    BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-kid-absent-single-jwks":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-kid-absent-single-jwks".format(
                    BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-missing-at_hash":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-missing-at_hash".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-sig+enc":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-sig+enc".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-sig+enc-a128kw":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-sig+enc-a128kw".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-sig-es256":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-sig-es256".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-sig-hs256":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-sig-hs256".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-sig-rs256":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-sig-rs256".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-id_token-sub":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-id_token-sub".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-key-rotation-op-enc-key":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-key-rotation-op-enc-key".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-key-rotation-op-sign-key":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-key-rotation-op-sign-key".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-key-rotation-op-sign-key-native":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-key-rotation-op-sign-key-native".format(
                    BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-nonce-invalid":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-nonce-invalid".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-nonce-unless-code-flow":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-nonce-unless-code-flow".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-registration-dynamic":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-registration-dynamic".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-request_uri-enc":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-request_uri-enc".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-request_uri-sig":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-request_uri-sig".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-request_uri-sig+enc":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-request_uri-sig+enc".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-request_uri-unsigned":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-request_uri-unsigned".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-response_mode-form_post":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-response_mode-form_post".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-response_type-id_token+token":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-response_type-id_token+token".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-scope-userinfo-claims":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-scope-userinfo-claims".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-userinfo-bad-sub-claim":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-userinfo-bad-sub-claim".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-userinfo-bearer-body":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-userinfo-bearer-body".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-userinfo-bearer-header":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-userinfo-bearer-header".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-userinfo-enc":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-userinfo-enc".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-userinfo-sig":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-userinfo-sig".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
    "rp-userinfo-sig+enc":
        {
            "issuer": "{}/{}/".format(TESTTOOL_URL, TESTER_ID),
            "redirect_uris": [
                "{}/authz_cb/rp-userinfo-sig+enc".format(BASEURL)],
            "client_prefs": {
                "application_type": "web",
                "application_name": "rphandler",
                "contacts": ["ops@example.com"],
                "response_types": ["id_token token"],
                "scope": ["openid", "profile", "email", "address", "phone"],
                "token_endpoint_auth_method": ["client_secret_basic"],
            },
            "services": {
                "ProviderInfoDiscovery": {},
                "Registration": {},
                "Authorization": {},
                "AccessToken": {}
            }
        },
}
