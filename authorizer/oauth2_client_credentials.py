import jwt
import json
import boto3
from jwks_utils import rsa_pem_from_jwk  

import os

"""
issuer = "https://<acct>.okta.com/oauth2/default"
valid_audiences = ["aud-name"]
We can replace above with os.env["ISSUER_URL"] and os.env["VALID_AUDIENCE"]
Make sure these env values are set for your authorization lambda
"""
issuer = os.environ["ISSUER_URL"]
valid_audiences = os.environ["VALID_AUDIENCE"]

"""   
Get the keys from /.well-known/oauth-authorization-server endpoint. Encrypt and store them in AWS 
ParameterStore. Sample jwks values shown below.
jwks = {"keys":[
            {"kty":"RSA",
            "alg":"RS256",
            "kid":"----",
            "use":"sig",
            "e":"AQAB",
            "n":"-------"},
            {"kty":"RSA",
            "alg":"RS256",
            "kid":"-----------",
            "use":"sig",
            "e":"AQAB",
            "n":"------"}
        ]}
        
"""
ssm = boto3.client('ssm')
parameter = ssm.get_parameter(Name='okta_jwks_wsmessage', WithDecryption=True)
value = parameter['Parameter']['Value']
jwks = json.loads(value)

class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)


def get_kid(token):
    headers = jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing headers')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidAuthorizationToken('missing kid')


def get_jwk(kid):
    for jwk in jwks.get('keys'):
        if jwk.get('kid') == kid:
            return jwk
    raise InvalidAuthorizationToken('kid not recognized')


def get_public_key(token):
    return rsa_pem_from_jwk(get_jwk(get_kid(token)))


def validate_jwt(jwt_to_validate):
    public_key = get_public_key(jwt_to_validate)

    decoded = jwt.decode(jwt_to_validate,
                         public_key,
                         verify=True,
                         algorithms=['RS256'],
                         audience=valid_audiences,
                         issuer=issuer)
    
    # do what you wish with decoded token:
    # if we get here, the JWT is validated
    print(decoded)
    return decoded