# Elliptic Curve Cryptographic system
# uses curve P-256 as default for generating private key

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EllipticCurveSystem:

    def __init__(self, private_key=None):
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1())

        self.private_key = private_key
        self.public_key = private_key.public_key()

    def create_pem(self) -> bytes:
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def derive_shared_secret(self, peer_public_key, salt=None) -> tuple[bytes, bytes]:
        """Derive shared secret using Elliptic-curve Diffie-Hellman (ECDH)"""
        if salt is None:
            salt = os.urandom(16)
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        ).derive(shared_secret)
        return salt, derived_key

    def encrypt_message(self, peer_public_key, message: bytes) -> tuple[bytes, bytes, bytes, bytes]:
        """Encrypt a message using a symmetric key derived from a shared secret."""
        salt, symmetric_key = self.derive_shared_secret(peer_public_key)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

        return (salt, nonce, ciphertext, encryptor.tag)

    def decrypt_message(
        self,
        peer_public_key: bytes,
        salt: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes
    ) -> str:
        """Decrypt a message using a symmetric key derived from a shared secret."""
        _, symmetric_key = self.derive_shared_secret(peer_public_key, salt)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode("utf-8")

    def sign_message(self, message: bytes) -> bytes:
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, message: bytes, signature: bytes):
        try:
            self.public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            print("The signature is valid!")
        except Exception as e:
            print(e.__class__.__name__)
            print("The signature is invalid!")



if __name__ == "__main__":

    # Two parties want to speak in secret:    
    message = "foo bar".encode("utf-8")
    ecc = EllipticCurveSystem()
    ecc_peer = EllipticCurveSystem()

    # Generate the shared secret to encrypt messages with:
    peer_public_key_serialized = ecc_peer.create_pem()
    peer_public_key = serialization.load_pem_public_key(peer_public_key_serialized)
    shared_secret = ecc.derive_shared_secret(peer_public_key)

    # Encrypt the message:
    encrypted_msg = ecc.encrypt_message(peer_public_key, message)

    # Decrypt the message:
    decrypted_msg = ecc.decrypt_message(
        peer_public_key=peer_public_key,
        salt=encrypted_msg[0],
        nonce=encrypted_msg[1],
        ciphertext=encrypted_msg[2],
        tag=encrypted_msg[3])

    print(decrypted_msg)
