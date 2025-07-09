from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import jwt, time, os

from app.repository import is_blacklisted

def generate_rsa_key_pair():
    # generate a new RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # serialize the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # generate the public key from the private key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def sign_vote(private_key_content, vote_data):
    # load the private key, and in case it isn a valid format, returns False
    try:
        private_key = serialization.load_pem_private_key(
            private_key_content,
            password=None
        )
    except:
        return False

    # sign the vote data
    signed_vote = private_key.sign(
        vote_data.encode('utf-8'),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA256()
    )

    return signed_vote


def verify_signature(signed_data, public_key_content, original_vote_data):
    public_key = serialization.load_pem_public_key(public_key_content)
    try:
        public_key.verify(
            signed_data,
            original_vote_data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False



HMAC_SECRET = open("hmac_key.pem", "rb").read()
JWT_EXPIRATION = 1800

def generate_jwt(user_id):
    # generates the payload for the JWT with the user_id claim
    payload = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRATION,
        "jti": str(os.urandom(16).hex()),
    }

    # signs the JWT with the HMAC secret
    token = jwt.encode(payload, HMAC_SECRET, algorithm="HS256")
        
    return token


def verify_jwt(token):
    # checks if the token is valid and returns the payload if it is, otherwise returns None
    try:
        payload = jwt.decode(token, HMAC_SECRET, algorithms=["HS256"])
        if is_blacklisted(payload.get('jti')):
            return None
        return payload
    
    except jwt.ExpiredSignatureError:
        return None
    
    except jwt.InvalidTokenError:
        return None


def get_jti(token):
    # returns the JTI (JWT ID) from the token if it is valid, otherwise returns None
    payload = verify_jwt(token)
    if payload is None:
        return None
    return payload.get('jti')