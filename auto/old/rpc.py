import enum, asyncio, websockets, json, ssl
from typing import Any, Optional, Union, Dict, List, Literal, Callable, Any
from pydantic import BaseModel
from cryptography.X509 import Certificate

class JSONRPCRequest(BaseModel):
    jsonrpc = Literal["2.0"]
    method: str
    params: Union[list, dict, None] = None
    id: Optional[Union[int, str]] = None

class JSONRPCResponse(BaseModel):
    jsonrpc = Literal["2.0"]
    result: Optional[Any] = None
    error: Optional[Any] = None
    id: Optional[Union[int, str]] = None

class Message(BaseModel):
    request: Optional[JSONRPCRequest] = None
    response: Optional[JSONRPCResponse] = None

class EntityType(enum.Enum):
    """An enumeration of entity types within the Autonomous Identity (Auto ID) framework that may communicate over the Auto RPC protocol."""

    CONTROLLER = "Controller"
    """A controller is a type of issuing entity that can self-cerity its own identity and the identities of subject entities. Controllers typically represent human users on a mobile app"""

    AGENT = "Agent"
    """An agent is a type of subject entity that must receive a certification from an issuer. Agents are typically autonomous AI systems that can act on behalf of a controller. Agents typically run on a server."""

    REGISTRAR = "Registrar"
    """A registrar is a type of subject entity that submits transaction to the registry on behalf of other entities. It is typically an automated service that runs on a server. """

    GRANTER = "Granter"
    """An granter is a type of entity that may grant credentials to other entities, based on attribute or access claims that the Granter can attest to. Granters typically represent organizations or businesses and are considered trusted entities. Granters may be issuing entities, controllers or even agents acting on behalf of controllers. Granters typically run on a server."""

    GATEWAY = "Gateway"
    """A gateways is a type of subject entity that can relay messages between other entities. Gateways are often used by controllers who wish to run their agents locally and need to make them addressable over the public internet. It are always an automated service that runs on a server. """

class RPCNode(BaseModel):
    """
    An RPC node which can be run as a server, client, or some combination of both. Both services and clients can call the RPC methods of any connected nodes. Clients can initiate a connection to a server. Servers can also connect to other servers.

    Exposes a JSON-RPC service over WS and WSS interface. Uses the Websockets library to create a server and client. Uses the JSON-RPC library to create a JSON-RPC service. Uses the SSL library to create a secure TLS channel over WSS.

    An RPC node instance is created by each entity class. The entity will only call a subset of methods based on its role. For example, a controller will only call the `connect` method, while an agent will only call the `start_service` method.

    """

    entity_type: EntityType
    contacts: Dict[str, Certificate] = {}  # Mapping from entity ID to Certificate
    server: Optional[asyncio.Server] = None
    websocket: Optional[websockets.WebSocketClientProtocol] = None
    
    def __init__(self, entity_type: EntityType, certificate: Optional[Certificate], **kwargs):
        super().__init__(**kwargs)
        self.entity_type = entity_type
        if certificate:
            self.certiifcate = certificate
        # create an inbox for new messages, messaages are removed once they are marked done by the handler
        # create an outbox for outgoing messages, messages are removed once the receiver acknowledges receipt
        # create a simple contacts database that can be persisted to disk and loaded on startup, certificates are stored here
            

    def validate_certificate(self, certificate: Certificate, verify: Callable) -> bool:
        """Validate a certificate for the entity."""
        # Implement certificate validation logic here
        # This should involve verifying the signature, checking the issuer, and checking the subject
        return verify(certificate)


    async def _process_rpc_request(self, request: dict) -> Any:
        """Process JSON-RPC request and generate a response."""
        # Implement JSON-RPC request processing logic here
        # This should involve identifying the method, executing it, and capturing the result or error
        # Example response for a method that echoes back the params
        if request.get("method") == "echo":
            response = {"jsonrpc": "2.0", "result": request.get("params"), "id": request.get("id")}
        else:
            response = {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": request.get("id")}
        return response

    async def _rpc_handler(self, websocket: websockets.WebSocketServerProtocol, path: str):
        """Handle incoming JSON-RPC requests."""
        async for message in websocket:
            try:
                data = json.loads(message)
                # Assuming you have a method to process the JSON-RPC request and return a response
                response = await self._process_rpc_request(data)
                await websocket.send(json.dumps(response))
            except Exception as e:
                # Handle exception, e.g., parsing error, method not found, etc.
                error_response = {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": None}
                await websocket.send(json.dumps(error_response))

    async def start_service(self, host: str = 'localhost', port: int = 8765):
        """Expose the RPC service over a public address."""
        ssl_context = None  # Define your SSL context for WSS or leave as None for WS
        self.server = websockets.serve(self._rpc_handler, host, port, ssl=ssl_context) # type: ignore

        print(f"RPC Service is listening on {'ws' if ssl_context is None else 'wss'}://{host}:{port}")

    # def connect(self):
    #     """Connect to an RPC service node. Initiates an insecure channel, typically only used to allow new agents to connect to controllers and certify their public keys. The connection is then upgraded to a secure channel over WSS using an Auto ID Certificate. Every newly connected node is added to the local contacts database, along with its certificate. On subsequent connections the certificate is used to automatically upgrade the connection to a secure channel."""
    #     pass

    async def connect(self, uri: str, secure: bool = False):
        """"""
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) if secure else None
        # Load certificates if secure...

        self.websocket = await websockets.connect(uri, ssl=ssl_context)
        # Example of sending a JSON-RPC request immediately upon connection
        await self._send(JSONRPCRequest(method="hello", params=["RPCNode"], id=1))

        # You might want to keep the connection open or listen for incoming messages here

    async def _send(self, message: Union[JSONRPCRequest, JSONRPCResponse]):
        """Send a message to a connected RPC node."""
        if self.websocket and self.websocket.open:
            message_json = message.model_dump_json() # Serialize the Pydantic model to a JSON string
            await self.websocket.send(message_json)
        else:
            print("WebSocket connection is not open.")

    async def send_echo(self, message: str, message_id: Union[int, str] = 1):
        """Send an echo message to the connected RPC node."""
        echo_request = JSONRPCRequest(method="echo", params=[message], id=message_id)
        await self._send(echo_request)

    async def disconnect(self):
        """Disconnect from the RPC service node."""
        if self.websocket and not self.websocket.closed:
            await self.websocket.close()
            print("Disconnected from the server.")
        self.websocket = None

    async def stop_service(self):
        """Stop the RPC service."""
        if self.server:
            self.server.close()  # Schedule the server to close
            await self.server.wait_closed()  # Wait until the server is closed
            print("RPC Service has been stopped.")
        self.server = None

    """
    TODO:
        - Assume any two parties have pinned public keys out of band
        - only expose secure connections over TLS
        - add each new connection to a connection manager, allowing for multiple client connections, requrires addressing for sending
        - define message object as pydantic models for each JSON-RPC request and response
        - ensure messages are added to queues for reliable delivery
        
    """