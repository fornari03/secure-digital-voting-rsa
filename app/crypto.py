from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

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
    # load the private key
    private_key = serialization.load_pem_private_key(
        private_key_content,
        password=None
    )

    # sign the vote data
    signed_vote = private_key.sign(
        vote_data.encode('utf-8'),
        padding=serialization.PKCS1v15(),
        algorithm=serialization.HashAlgorithm()
    )

    return signed_vote

def verify_signature(signed_data, public_key_content, original_vote_data):
    # 
    public_key = serialization.load_pem_public_key(public_key_content)
    try:
        public_key.verify(
            signed_data,
            original_vote_data.encode('utf-8'),
            padding.PKCS1v15(),
            serialization.HashAlgorithm()
        )
        return True
    except Exception:
        return False
    

def generate_jwt(user_id):
    # TODO: implement JWT generation logic
    pass

def verify_jwt(token):
    # TODO: implement JWT verification logic
    pass

def get_jti(token):
    # TODO: implement logic to extract JTI from JWT
    pass