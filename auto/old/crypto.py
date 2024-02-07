
# from typing import Optional, Tuple
# import enum, os
# from pydantic import BaseModel
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
# from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
# from cryptography.exceptions import InvalidSignature
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes

# class Certificate(BaseModel):
#     """A class for handling X.509 conformant certificates for Auto IDs."""
#     issuer: str
#     subject: str
#     validity: object
#     serial_number: int
#     public_key: bytes
#     signature_algorithm: str
#     signature: bytes

# class SignatureAlgorithm(enum.Enum):
#     ED25519 = "Ed25519"

# #TODO: generate keys from seed deterministically

# def generate_eddsa_25519_keypair() -> Tuple[bytes, bytes]:
#     """ Generate an EdDSA keypair under curve 25519 using the cryptography library. """
#     private_key = Ed25519PrivateKey.generate()
#     public_key = private_key.public_key()
    
#     # Convert the keys to bytes
#     private_key_bytes = private_key.private_bytes(
#         encoding=Encoding.Raw,
#         format=PrivateFormat.Raw,
#         encryption_algorithm=NoEncryption()
#     )

#     public_key_bytes = public_key.public_bytes(
#         encoding=Encoding.Raw,
#         format=PublicFormat.Raw
#     )
    
#     return public_key_bytes, private_key_bytes

# def sign_eddsa_25519(message: bytes, private_key_bytes: bytes) -> bytes:
#     """ Sign a message using the private key of an EdDSA keypair. """
#     private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
#     signature = private_key.sign(message)
#     return signature

# def verify_eddsa_25519(message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
#     """ Verify a signature using the public key of an EdDSA keypair. """
#     public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
#     try:
#         # Attempt to verify the signature
#         public_key.verify(signature, message)
#         return True
#     except InvalidSignature:
#         return False
    
# def generate_random_id() -> str:
#     """ Generates a 32-byte random value and computes its SHA-256 hash. """
#     random_value = os.urandom(32)
#     hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
#     hasher.update(random_value)
#     hash_value = hasher.finalize()
#     return hash_value.hex()

# class KeyPair(BaseModel):
#     """A class for handling crytpographic key pairs. Used by entities to create and manage keys and sign messages."""

#     signature_algorithm: SignatureAlgorithm
#     public_key: bytes
#     private_key: bytes

#     def __init__(self, signature_algorithm: SignatureAlgorithm, **data):
#         super().__init__(**data)  # Initialize BaseModel with provided data
#         self.signature_algorithm = signature_algorithm
#         if not (self.public_key and self.private_key):
#             self.generate_keys()

#     def generate_keys(self, seed: Optional[str] = None):
#         """Generate a new key pair and update instance attributes."""
#         public_key_bytes, private_key_bytes = generate_eddsa_25519_keypair()
#         self.public_key = public_key_bytes
#         self.private_key = private_key_bytes

#     @staticmethod
#     def from_bytes(public_key: bytes, private_key: bytes, signature_algorithm: SignatureAlgorithm) -> 'KeyPair':
#         """Create a KeyPair object from provided public and private key bytes."""
#         return KeyPair(signature_algorithm=signature_algorithm, public_key=public_key, private_key=private_key)
    
#     def to_bytes(self) -> Tuple[bytes, bytes]:
#         """Return the public and private keys as a tuple of bytes."""
#         return self.public_key, self.private_key

#     def to_encoded_public_key(self) -> bytes:
#         """Returns the PEM encoded public key."""
#         public_key = Ed25519PublicKey.from_public_bytes(self.public_key)
#         return public_key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    
#     def to_encoded_private_key(self) -> bytes:
#         """Returns the PEM encoded private key."""
#         private_key = Ed25519PrivateKey.from_private_bytes(self.private_key)
#         return private_key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())

#     def sign_message(self, message: str) -> bytes:
#         """Sign a message using the private key."""
#         if self.signature_algorithm == SignatureAlgorithm.ED25519:
#             return sign_eddsa_25519(message.encode(), self.private_key)
#         else:
#             raise ValueError(f"Unsupported signature algorithm: {self.signature_algorithm}")

# class PublicKey(BaseModel):
#     signature_algorithm: SignatureAlgorithm
#     public_key: bytes

#     def __init__(self, signature_algorithm: SignatureAlgorithm, public_key: bytes, **data):
#         super().__init__(**data)  # Initialize BaseModel with provided data
#         self.signature_algorithm = signature_algorithm
#         self.public_key = public_key

#     @staticmethod
#     def from_encoded_public_key(encoded_public_key: bytes, signature_algorithm: SignatureAlgorithm) -> 'PublicKey':
#         """Create a Key object from the provided encoded public key."""
#         # Assuming the encoded_public_key is in PEM format for this example
#         if signature_algorithm == SignatureAlgorithm.ED25519:
#             public_key = Ed25519PublicKey.from_public_bytes(encoded_public_key)
#             encoded_public_key = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
#         else:
#             raise ValueError(f"Unsupported signature algorithm: {signature_algorithm}")
#         return PublicKey(signature_algorithm=signature_algorithm, public_key=encoded_public_key)
    
#     @staticmethod
#     def from_certificate(certificate: Certificate) -> 'PublicKey':
#         """Create a PublicKey object from a Certificate object."""
#         signature_algorithm = SignatureAlgorithm(certificate.signature_algorithm)
#         return PublicKey(signature_algorithm=signature_algorithm, public_key=certificate.public_key)
    
#     def verify_signature(self, signature: bytes, message: str) -> bool:
#         """Verify a signature using the public key of an EdDSA keypair."""
#         if self.signature_algorithm == SignatureAlgorithm.ED25519:
#             return verify_eddsa_25519(message.encode(), signature, self.public_key)
#         else:
#             raise ValueError(f"Unsupported signature algorithm: {self.signature_algorithm}")
