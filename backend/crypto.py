from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Convert public key to bytes (to send over network)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_bytes

def load_public_key(public_bytes):
    return serialization.load_pem_public_key(public_bytes)

def derive_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

def derive_aes_key(shared_secret):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)

    return derived_key

def encrypt_message(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return nonce, ciphertext

def decrypt_message(key, nonce, ciphertext):
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode()