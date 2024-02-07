import ssl, websockets, os
from websockets import serve
from websockets.legacy.server import WebSocketServerProtocol, WebSocketServer
from websockets.legacy.client import WebSocketClientProtocol 
from jsonrpcserver import method, Success, Result, async_dispatch
from jsonrpcclient import Ok, parse_json, request_json
from typing import Dict, Optional

#TODO:load ssl context from entity 
#TODO trust on first user with user notification
#TODO method to add trusted certificates, persist to disk, and load on startup
#TODO method to exchange certificates over the wire and validate with the regsitry
#TODO change ports for multiple nodes
#TODO handle reconnects
#TODO define RPC methods
#TODO define run all command

class RPCNode():
    """A network node which can speak the Auto ID JSON-RPC protocol over WSS using Auto ID TLS certificates."""

    wss_host: str
    wss_port: int
    cert_path: str
    key_path: str
    server_ssl_context: ssl.SSLContext
    client_ssl_context: ssl.SSLContext
    inbound_connections: Dict[str, WebSocketServerProtocol]
    outbound_connections: Dict[str, WebSocketClientProtocol]
    server: Optional[WebSocketServer]
    
    def __init__(
        self, 
        certificate_file_path: str = 'certificate.pem', 
        private_key_file_path: str = 'private_key.pem',
        wss_host: str = 'localhost',
        wss_port: int = 8765
    ) -> None:
        self.cert_path = certificate_file_path
        self.key_path = private_key_file_path
        self.wss_host = wss_host
        self.wss_port = wss_port
        self.uri = f"wss://{self.wss_host}:{self.wss_port}"

        if not os.path.exists(self.cert_path) or not os.path.exists(self.key_path):
            raise FileNotFoundError("Certificate or private key file does not exist.")
        
        self.set_ssl_context()
        self.connections = {}        
            
    def set_ssl_context(self):
        """Set an SSL context for WSS."""
        # Create server SSL context
        self.server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        self.server_ssl_context.load_cert_chain(
            certfile=self.cert_path, 
            keyfile=self.key_path, 
            password=b'password'
        )

        self.server_ssl_context.load_verify_locations(cafile=self.cert_path)
        self.server_ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.server_ssl_context.check_hostname = False

        # Create client SSL context
        self.client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
       
        self.client_ssl_context.load_cert_chain(
            certfile=self.cert_path, 
            keyfile=self.key_path,
            password=b'password'
        )

        self.client_ssl_context.load_verify_locations(cafile=self.cert_path)
        self.client_ssl_context.verify_mode = ssl.CERT_REQUIRED
        self.client_ssl_context.check_hostname = False
        
    async def connect(self, hostname: str, uri: str):
        """Connect to a node over WSS."""
        try: 
            ws = await websockets.connect(uri, ssl=self.client_ssl_context)
            self.connections[hostname] = ws
            print(f"Connected to {hostname} at {uri}")
        except Exception as e:
            print(f"Failed to connect to {hostname} at {uri}: {e}")

    async def send(self, hostname: str, method: str, *params):
        """Send a JSON-RPC request to a connected node."""
        if ws := self.connections.get(hostname):
            request = request_json(method, *params)
            await ws.send(request)
            response = parse_json(await ws.recv())
            if isinstance(response, Ok):
                print(response.result)
            else:
                print(response.message)
        else:
            print(f"No connection to {hostname}")

    async def close_connection(self, hostname: str):
        """Close a connection to a node."""
        if ws := self.connections.get(hostname):
            await ws.close()
            del self.connections[hostname]
            print(f"Closed connection to {hostname}")
        else:
            print(f"No connection to {hostname}")

    async def run_server(self, websocket: WebSocketServerProtocol, path):
        """Run the WSS server. For each new connection, get the client's TLS certificate and store the connection."""

        ssl_object = websocket.transport.get_extra_info('ssl_object')
        peer_cert = ssl_object.getpeercert()
        subject = dict(x[0] for x in peer_cert['subject'])
        common_name: str = subject.get('commonName') # type: ignore
        self.inbound_connections[common_name] = websocket
        try:
            while True:
                message = await websocket.recv()
                # Dispatch the message to the appropriate handler based on the message content
                response = await async_dispatch(message)
                await websocket.send(response)
        except websockets.exceptions.ConnectionClosed:
            del self.connections[common_name]

    async def start_service(self):
        """Expose the RPC service over a public address with TLS."""
        self.server = await serve(self.run_server, self.wss_host, self.wss_port, ssl=self.server_ssl_context)

    async def close_server(self):
        """Close the RPC server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("Server closed.")
            self.server = None

    async def close_all(self):
        """Close all connections and the server."""
        # Close all client connections
        for hostname in list(self.connections.keys()):
            await self.close_connection(hostname)
        # Then close the server
        await self.close_server()

    @method()
    async def ping(self, name: str) -> Result:
        return Success("pong")
    
    @method()
    async def invite() -> Result:
        return Success("invited")
    
    

    



