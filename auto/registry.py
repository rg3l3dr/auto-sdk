from substrateinterface import SubstrateInterface, Keypair, exceptions, ExtrinsicReceipt
from typing import Optional
from cryptography import x509

class Registry():
    """A class for interacting with the Auto ID registry contract on the Substrate blockchain."""

    def __init__(self, name: Optional[str]):
        self.registry = SubstrateInterface(url="ws://127.0.0.1:9944")
        self.signer: Optional[Keypair] =  None

        if name is not None:
            self.signer =  Keypair.create_from_uri(f'//{name}')

    def _compose_call(self, call_function: str, call_params: dict) -> Optional[ExtrinsicReceipt]:
        """Composes an extrinsic and call the registry module."""
        if self.signer is None:
            return None

        call = self.registry.compose_call(
            call_module='Registry',
            call_function=call_function,
            call_params=call_params,
        )

        extrinsic = self.registry.create_signed_extrinsic(call=call, keypair=self.signer)

        try:
            return self.registry.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        except exceptions.SubstrateRequestException as e:
            print("Failed to send: {}".format(e))
            return None

    def register(
            self,
            certificate: x509.Certificate
        ) -> bool:
        """Registers a signed certficate with the registry. Returns an X.509 conformant certificate or None if the registration failed."""

        receipt = self._compose_call(
            'register_entity', 
            {
                'certificate': certificate, 
            }
        )

        if receipt is None or receipt.is_success is False:
            return False
        
        registration_event = receipt.triggered_events[0]
        return True

    def get_certificate(
            self, 
            identifier: str
        ) -> Optional[x509.Certificate]:
        """Retrieves a certificate from the registry."""
        result = self.registry.query('Registry', 'Entity', [identifier])

        if result is None:
            return None
        
        certificate = x509.load_pem_x509_certificate(result['certificate'].encode('utf-8'))

        return certificate
    
    def verify(
            self, 
            identifier: str, 
            public_key: bytes
        ) -> bool:
        """Verifies an entity with a given identifier and public key is registerd with the registry."""
        result = self.registry.query('Registry', 'Entity', [identifier])
        
        if result['public_key'] != public_key:
            return False
        
        #TODO: correct time check
        if result['validity'] < 0:
            return False

        return True

    def renew(
            self,
            subject: str,
            public_key: bytes,
            signature: bytes
        ) -> bool:
        """ Renews a registered certificate for a given entity. Returns an X.509 conformant certificate or None if the renewal failed."""
        receipt = self._compose_call(
            'renew_entity', 
            {
                'subject': subject, 
                'public_key': public_key, 
                'signature': signature
            }
        )

        if receipt is None or receipt.is_success is False:
            return False
        
        renewal_event = receipt.triggered_events[0]
        return True

    def revoke(
            self,
            subject: str,
            nonce: str,
            signature: bytes
        ) -> bool:
        """Revokes a registered certificate for a given entity. Returns a boolean indicating success or failure."""
        receipt = self._compose_call(
            'revoke_entity', 
            {
                'subject': subject, 
                'nonce': nonce, 
                'signature': signature
            }
        )

        if receipt is None or receipt.is_success is False:
            return False
        
        return True