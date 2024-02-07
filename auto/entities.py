from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import datetime, os
from auto.registry import Registry
from auto.rpc import RPCNode
from abc import ABC
from auto.api import APIServer
import ssl, requests, time

# TODO: registrar must be a subject or issuer
# TODO: make private key password an environment variable
# TODO: ask Nazar to fix the implmentation of the registry, first proof in solidity
# TODO: decide how to check if or when trusted certificates have been revoked 


class Entity(ABC):
    id: str
    name: x509.Name
    public_key: ed25519.Ed25519PublicKey
    private_key: ed25519.Ed25519PrivateKey
    certificate: x509.Certificate
    registry: Registry
    trusted_certs_dir: str
    wss_ssl_context: ssl.SSLContext


    def __init__(
            self, 
            identifier: str,
            trusted_certs_dir: str = "trusted_certs"
        ):
        self.id = identifier
        self.trusted_certs_dir = trusted_certs_dir
        self.registry = Registry(name=None)

        # load if identity exists
        if os.path.exists(os.path.join(self.trusted_certs_dir, self.id + ".pem")):
            self.load()
        else:
            os.makedirs(self.trusted_certs_dir, exist_ok=True)

    def load(self):
        self.load_keys()
        self.load_own_certificate()
        self.load_trusted_certificates_to_ssl_context()

    def create_name(self):
        self.name = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.id),
        ])

    def create_keys(self):
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def save_private_key(self):
        with open("private_key.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password=b"password"),
            ))

    def load_keys(self):
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

            if isinstance(private_key, ed25519.Ed25519PrivateKey):
                self.private_key = private_key
            else:
                raise ValueError("Invalid key type")

            self.public_key = private_key.public_key()


        self.public_key = self.private_key.public_key()

    def create_csr(self) -> x509.CertificateSigningRequest:
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            self.name
        ).sign(self.private_key, hashes.SHA256())

        return csr
    
    def validate_preregistered_self_signed_certificate(self, certificate: x509.Certificate) -> bool:
        """Validates a self-signed certificate, created by an issuer, before submitting it to the registry."""

        if certificate.subject != certificate.issuer:
            raise ValueError("Invalid certificate issuer")

        if certificate.signature_algorithm_oid != x509.SignatureAlgorithmOID.ED25519:
            raise ValueError("Invalid signature algorithm")
        
        if certificate.public_key() != ed25519.Ed25519PublicKey:
            raise ValueError("Invalid public key type")
        
        if certificate.not_valid_before > datetime.datetime.utcnow():
            raise ValueError("Certificate not yet valid")
        
        if certificate.not_valid_after < datetime.datetime.utcnow():
            raise ValueError("Certificate expired")
        
        try:
            public_key = certificate.public_key()

            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise ValueError("Invalid public key type")

            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
            return True
        
        except InvalidSignature:
            return False
    
    def validate_preregistered_certificate(
            self, 
            certificate: x509.Certificate, 
            issuer_certificate: x509.Certificate
        ) -> bool:
        """Validates that a certificate returned by an issuer, before submitting it to the registry."""

        #TODO ensure the issuer has not tampered with the certificate, i.e. it matches the CSR exactly

        if certificate.signature_algorithm_oid != x509.SignatureAlgorithmOID.ED25519:
            raise ValueError("Invalid signature algorithm")
        
        if certificate.public_key() != ed25519.Ed25519PublicKey:
            raise ValueError("Invalid public key type")
        
        if certificate.not_valid_before > datetime.datetime.utcnow():
            raise ValueError("Certificate not yet valid")
        
        if certificate.not_valid_after < datetime.datetime.utcnow():
            raise ValueError("Certificate expired")
        
        try:

            issuer_public_key = issuer_certificate.public_key()

            if not isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
                raise ValueError("Invalid public key type")

            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
            return True
        
        except InvalidSignature:
            return False
        
    def validate_certificate_is_registered(self, certificate: x509.Certificate) -> bool:
        """Validates that a certificate is registered with the registry. Called by any entity during certificate validation."""

        id = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        if isinstance(id, bytes):
            id = id.decode("utf-8")

        return self.registry.verify(id, certificate.public_key().public_bytes( # type: ignore
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))

    def save_own_certificate(self, certificate: x509.Certificate):
        cert_path = os.path.join(self.trusted_certs_dir, self.id + ".pem")
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

    def save_and_trust_certificate(self, certificate: x509.Certificate):
        id = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

        if isinstance(id, bytes):
            id = id.decode("utf-8")

        cert_path = os.path.join(self.trusted_certs_dir, id + ".pem") # type: ignore
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # add to ssl context
        self.trust_certificate(id) # type: ignore

    def trust_certificate(self, id: str):
        cert_path = os.path.join(self.trusted_certs_dir, id + ".pem")
        with open(cert_path, "rb") as f:
            self.wss_ssl_context.load_verify_locations(cafile=cert_path)
        
    def load_own_certificate(self):
        with open("certificate.pem", "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())

    def load_trusted_certificates_to_ssl_context(self):
        for cert in os.listdir(self.trusted_certs_dir):
            if cert.endswith(".pem"):
                self.trust_certificate(cert)
        
class Subject(Entity, ABC):
    """An entity that can be issued X.509 certificates."""
    issuer: x509.Certificate

    def __init__(self, identifier: str, issuer: x509.Certificate):
        super().__init__(identifier)
        self.validate_certificate_is_registered(issuer)
        self.controller = issuer

class Issuer(Entity, ABC):
    """An entity that can issue X.509 certificates."""

    next_serial_number: int = 0

    def __init__(self, identifier: str):
        super().__init__(identifier)
    
    def sign_csr(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        """Signs a certificate signing request (CSR) to create a certificate on behalf of a subject entity."""

        certificate =  x509.CertificateBuilder().subject_name(
            csr.subject,
        ).issuer_name(
            self.name,
        ).public_key(
            csr.public_key(),
        ).serial_number(
            self.next_serial_number,
        ).not_valid_before(
            datetime.datetime.utcnow(),
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365),
        ).sign(self.private_key, hashes.SHA256())

        self.next_serial_number += 1
        self.save_and_trust_certificate(certificate)
        return certificate
    
    def self_issue(self) -> x509.Certificate:
        """Self-issues a certificate for the issuer."""
        self.create_name()
        self.create_keys()
        csr = self.create_csr()
        certificate = self.sign_csr(csr)
        if self.validate_preregistered_self_signed_certificate(certificate):
            self.save_own_certificate(certificate)
            return certificate
        else:
            raise ValueError("Failed to self-issue certificate")

class Registrar(Entity):
    """An entity that can register X.509 certificates."""

    def __init__(self, identifier: str):
        super().__init__(identifier)

    def register(self, certificate: x509.Certificate):
        """Registers a certificate with the registry, on behalf of an entity."""
        if certificate.issuer != certificate.subject:
            # certificate issued on behalf of another entity

            # verify the issuer is registered, and fetch the public key
            issuer_id = certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if isinstance(issuer_id, bytes):
                issuer_id = issuer_id.decode("utf-8")
                        
            issuer_cert = self.registry.get_certificate(issuer_id) # type: ignore
            if issuer_cert is None:
                raise ValueError("Issuer not registered")
            
            # ensure the issued certificate is valid
            if not self.validate_preregistered_certificate(certificate, issuer_cert):
                raise ValueError("Invalid certificate for issuer")

        else:
            # certificate self-issued by the entity

            # ensure the certificate is valid
            if not self.validate_preregistered_self_signed_certificate(certificate):
                raise ValueError("Invalid self-issued certificate")

        self.registry.register(certificate)

class Controller(Issuer):
    """An human entity that can issue X.509 certificates to its agent entities."""
    registrar: Registrar
    rpc: RPCNode

    def __init__(
            self, 
            identifier: str, 
            registrar: Registrar
        ):
        super().__init__(identifier)
        self.registrar = registrar
        
    def self_register(self) -> x509.Certificate:
        """ Creates a self-signed certificate and registers it with the registrar."""
        certificate = self.self_issue()
        self.registrar.register(certificate)
        return certificate
    
    def long_poll_for_agent_csr(self) -> x509.CertificateSigningRequest:
        """Long-polls a recently spawned agent for a certificate signing request (CSR)."""
        while True:
            response = requests.get("http://localhost:8000/get_unsigned_csr")
            if response.status_code == 200 and "unsigned_csr" in response.json():
                unsigned_csr = response.json()["unsigned_csr"]
                print(f"Received unsigned CSR: {unsigned_csr}")
                return unsigned_csr
            time.sleep(1)  # Wait before polling again

    #TODO: save and trust the certificate

    def post_signed_cert_to_agent(self, certificate: x509.Certificate):
        """Posts a signed certificate to the agent."""
        pem_cert = certificate.public_bytes(serialization.Encoding.PEM)        
        files = {'cert_file': ('cert_file.pem', pem_cert, 'application/x-pem-file')}
        response = requests.post("http://localhost:8000/put_signed_csr", files=files)
        if response.status_code == 200:
            print(response.json()["message"])
        else:
            print("Failed to post signed certificate:", response.status_code, response.text)

class Agent(Subject):
    registrar: Registrar
    rpc: RPCNode
    api: APIServer

    def __init__(
        self, 
        identifier: str, 
        controller: x509.Certificate, 
        registrar: Registrar
    ):
        super().__init__(identifier, controller)
        self.registrar = registrar
        self.save_and_trust_certificate(controller)

    #TODO: get the certificate on post_signed_certificate

    def register(self, certificate: x509.Certificate):
        self.validate_preregistered_certificate(certificate, self.issuer)
        self.registrar.register(certificate)
        self.save_own_certificate(certificate)