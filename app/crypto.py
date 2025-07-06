from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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


def sign_vote(private_key, vote_data):
    # TODO: implement signing (hash + encrypt) logic
    pass

def verify_signature(user_id, signed_data):
    # TODO: implement signature verification logic
    pass

def generate_jwt(user_id):
    # TODO: implement JWT generation logic
    pass

def verify_jwt(token):
    # TODO: implement JWT verification logic
    pass

def get_jti(token):
    # TODO: implement logic to extract JTI from JWT
    pass