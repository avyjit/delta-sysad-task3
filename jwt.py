import hmac
import json
import base64

ENCODING = 'ascii'

# im hardcoding it cuz im lazy
# but ill load from an environment variable
# for "production" lmao
SECRET_KEY = b"LOAD_FROM_ENVVAR_DUMBASS"

def compute_signature(string: str):
    signature = hmac.new(SECRET_KEY, string.encode(ENCODING), "sha256").digest()
    signature = base64.b64encode(signature).decode(ENCODING)
    return signature

def encode_token(username):

    return json.dumps({
        "username": username,
        "signature": compute_signature(username)
    })

def verify_token(token):
    token = json.loads(token)
    username = token["username"]
    computed = compute_signature(username)

    return computed == token["signature"]
