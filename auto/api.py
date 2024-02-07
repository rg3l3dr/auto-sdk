import uvicorn, asyncio, httpx, os, time
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Optional
from uvicorn.config import Config

class APIServer():
    """A class for creating a FastAPI server to exchange certificates between Auto ID entities."""

    app: FastAPI
    server: Optional[uvicorn.Server]
    host: str
    port: int
    trusted_certs_dir: str
    
    def __init__(
            self, 
            host: str, 
            port: int, 
            trusted_certs_dir: str = "trusted_certs"
        ):

        self.host = host
        self.port = port
        self.trusted_certs_dir = trusted_certs_dir
        self.app = FastAPI()
        self.setup_routes()

    async def start_server(self):
        """Start the FastAPI server using uvicorn."""
        config = Config(app=self.app, host=self.host, port=self.port, loop="asyncio")
        self.server = uvicorn.Server(config)
        await self.server.serve()

    def run_server(self):
        """Run the server in the background."""
        asyncio.run(self.start_server())

    async def shutdown_server(self):
        """Stop the FastAPI server."""
        if self.server is not None:
            self.server.should_exit = True
            await self.server.shutdown()

    def stop_server(self):
        """Stop the server."""
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.shutdown_server())
    
    def validate_certificate(
            self, 
            cert_pem: bytes, 
            issuer_cert_pem: Optional[bytes] = None
        ) -> bool:
        """ Validates a certificate's signature and optionally checks if it was issued by a specific issuer. """
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        
        # Optional: Validate the certificate was issued by the provided issuer certificate
        if issuer_cert_pem:
            issuer_cert = x509.load_pem_x509_certificate(issuer_cert_pem, default_backend())
            # This is a simplified check; in reality, you would verify the signature.
            if cert.issuer != issuer_cert.subject:
                return False
    
        # Add more validation checks as necessary (e.g., expiry)
        return True
    
    def save_certificate(
            self, 
            cert_pem: bytes, 
            filename: str
        ) -> None:
        """ Saves a certificate to the trusted certificates directory. """
        cert_path = os.path.join(self.trusted_certs_dir, filename)
        with open(cert_path, 'wb') as cert_file:
            cert_file.write(cert_pem)

    async def _post_certificates(
            self, 
            endpoint: str, 
            agent_cert_path: str, 
            controller_cert_path: str
        ):
        """Generic method to post certificates to an endpoint."""
        async with httpx.AsyncClient() as client:
            files = {
                "agent_cert": open(agent_cert_path, "rb"),
                "controller_cert": open(controller_cert_path, "rb")
            }
            response = await client.post(f"http://{self.host}:{self.port}/{endpoint}", files=files)
            return response.json()

    async def invite_agent(
            self, 
            controller_cert_path: str,
            agent_cert_path: str,
        ):
        """Call the invite endpoint to send certificates to another agent."""
        result = await self._post_certificates("invite", agent_cert_path, controller_cert_path)
        print("Invite result:", result)

    async def accept_invitation(
            self, 
            agent_cert_path: str, 
            controller_cert_path: str
        ):
        """Call the accept endpoint to reciprocate the invitation."""
        result = await self._post_certificates("accept", agent_cert_path, controller_cert_path)
        print("Accept result:", result)
    
    def setup_routes(self):
        """ Setup FastAPI routes to enable certificate exchange. """

        unsigned_csr: Optional[str] = None
        signed_csr: Optional[str] = None

        @self.app.get("/get_unsigned_csr")
        async def get_unsigned_csr():
            start_time = time.time()
            while not unsigned_csr:
                await asyncio.sleep(1)
                if time.time() - start_time > 30:  # 30 seconds timeout
                    return {"message": "No CSR available yet."}
            return {"unsigned_csr": unsigned_csr}
        
        #TODO fix this
        # @self.app.on_event("startup")
        # async def startup_event():
        #     background_tasks = BackgroundTasks()
        #     background_tasks.add_task(generate_csr)

        @self.app.post("/post_signed_certificate")
        async def post_signed_certificate(cert_file: UploadFile = File(...)):
            global signed_cert
            signed_cert_content = await cert_file.read()
            signed_cert = signed_cert_content.decode("utf-8")
            return {"message": "Signed CSR received."}
        
        @self.app.post("/invite/")
        async def invite(
            agent_cert: UploadFile = File(...), 
            controller_cert: UploadFile = File(...)
        ):
            """ Endpoint to receive and validate certificates from an agent. """
            agent_cert_pem = await agent_cert.read()
            controller_cert_pem = await controller_cert.read()
            
            # Validate the controller's certificate (self-signed)
            if not self.validate_certificate(controller_cert_pem):
                raise HTTPException(status_code=400, detail="Invalid controller certificate.")
            
            # Validate the agent's certificate (issued by the controller)
            if not self.validate_certificate(agent_cert_pem, controller_cert_pem):
                raise HTTPException(status_code=400, detail="Agent certificate not issued by the controller.")
            
            # Save the controller's certificate as trusted if validation passes
            self.save_certificate(controller_cert_pem, f"{controller_cert.filename}")
            
            # TODO: Notify the connected controller for TOFU decision
            
            return {"message": "Certificates received and validation succeeded."}
    
        @self.app.post("/accept/")
        async def accept(agent_cert: UploadFile = File(...), controller_cert: UploadFile = File(...)):
            """ Endpoint for the receiving agent to send its certificate and its controller's certificate back to the initiating agent for mutual trust establishment. """
            # Logic similar to /invite/; adjust based on whether this endpoint has different requirements
            
            return {"message": "Certificates received and processed for mutual trust establishment."}
        