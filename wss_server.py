"""
Simple secure websocket server implementation with self-signed certificate.

To generate root key use:
* openssl genrsa -out certs/rootca.key 4096

To generate root certificate use:
* openssl req -x509 -new -nodes -key certs/rootca.key -sha256 -days 1024 -out certs/rootca.crt

To view root certificate use:
* openssl x509 -in certs/rootca.crt -text -noout

To view server certificate use:
* openssl x509 -in certs/server.crt -text -noout

To be able to connect to the server the root certificate has to be added to the system as trusted root certificate authority
* Windows: https://docs.microsoft.com/en-us/skype-sdk/sdn/articles/installing-the-trusted-root-certificate
* Linux: https://ubuntu.com/server/docs/security-trust-store
* Chrome: https://support.google.com/chrome/a/answer/3505249?hl=en
* Android: https://support.google.com/pixelphone/answer/2844832?hl=en
* Ios: https://support.apple.com/en-us/HT204477 / https://kb.mit.edu/confluence/display/mitcontrib/Installing+Root+and+Personal+Certificates+on+iOS

Run server:
python3 wss_server.py

Connect to server:
Open debug tools in browser and run:

function wssClientTest() {
    const wssURL = 'wss://{host IP}:9999'; // TODO: change to your server IP

    const ws = new WebSocket(wssURL);

    // Handling the opening of the connection
    ws.onopen = () => {
        console.log('WSS connection has been opened.');
        // Sending a message to the server
        ws.send('Hello, this is the WSS client!');
    };

    // Handling incoming messages
    ws.onmessage = (event) => {
        console.log(`Received a message: ${event.data}`);
    };

    // Handling the closure of the connection
    ws.onclose = (event) => {
        console.log(`WSS connection has been closed with code: ${event.code} and reason: ${event.reason}`);
    };

    // Handling errors
    ws.onerror = (error) => {
        console.error(`An error occurred: ${error}`);
    };
    return ws;
}

// Calling the WSS client testing function
ws = wssClientTest();

Check for log: "Hello, this is the WSS client!"

Trobleshooting:
I am getting an error: "WSS connection has been closed with code: 1006"
Make sure that IP in js snippet is correct and root certificate is imported to your device.
"""

import logging
import OpenSSL.crypto
import asyncio
import websockets
import ssl
from pathlib import Path


logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)


def load_root_certificate() -> (OpenSSL.crypto.X509, OpenSSL.crypto.PKey):
    """Load root certificate and key from file"""

    root_ca_path = Path(__file__).parent / 'certs'
    root_ca_cert_path = root_ca_path / 'rootca.crt'
    root_ca_key_path = root_ca_path / 'rootca.key'

    with open(root_ca_cert_path, encoding='utf-8') as cert_file:
        root_ca_cert = OpenSSL.crypto.load_certificate(
            type=OpenSSL.crypto.FILETYPE_PEM, buffer=cert_file.read().encode())
    with open(root_ca_key_path, encoding='utf-8') as key_file:
        root_ca_key = OpenSSL.crypto.load_privatekey(
            type=OpenSSL.crypto.FILETYPE_PEM, buffer=key_file.read().encode())
    print(f"Server: root certificate loaded, cert={root_ca_cert_path}, key={root_ca_key_path}")
    return root_ca_cert, root_ca_key


def create_subj_alt_name_list():
    """Create subjectAltName list for certificate based on host IP addresses"""

    def get_host_ips():
        import socket
        hostname, alias_list, ipaddr_list = socket.gethostbyname_ex(socket.gethostname())
        print(f"get_host_ip: hostname={hostname} aliaslist={alias_list} "
                f"ipaddrlist={ipaddr_list}")
        return ipaddr_list

    host_ip_list = get_host_ips()
    subj_alt_name_formatted = ""
    for ip in host_ip_list:
        subj_alt_name_formatted += f'IP:{ip},'
    subj_alt_name_formatted = subj_alt_name_formatted[:-1]

    print(f"subjectAltName input {subj_alt_name_formatted}")
    return subj_alt_name_formatted


def generate_ip_cert(root_ca_cert: OpenSSL.crypto.X509,
                     root_ca_key: OpenSSL.crypto.PKey) -> (Path, Path):
    """Generate certificate for IP address"""

    print(f"generate cert for IP")
    server_cert_path = Path(__file__).parent / 'certs'
    server_cert_path.mkdir(parents=True, exist_ok=True)
    server_key_file = server_cert_path / "server.key"
    server_cert_file = server_cert_path / "server.crt"

    server_key = OpenSSL.crypto.PKey()
    server_key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    server_cert = OpenSSL.crypto.X509()
    server_cert.get_subject().C = 'PL'
    server_cert.get_subject().ST = 'n/a'
    server_cert.get_subject().L = 'n/a'
    server_cert.get_subject().O = 'Dummy organization'
    server_cert.get_subject().OU = 'Dummy unit'
    server_cert.get_subject().CN = 'Dummy name'
    server_cert.get_subject().emailAddress = 'dummy@email.com'
    server_cert.set_serial_number(0)
    server_cert.gmtime_adj_notBefore(0)
    server_cert.gmtime_adj_notAfter(60 * 60 * 24 * 365) # year
    server_cert.set_version(2)

    server_cert.add_extensions([
        OpenSSL.crypto.X509Extension('basicConstraints'.encode('utf-8'),
                                        True,
                                        "CA:FALSE".encode('utf-8')),
        OpenSSL.crypto.X509Extension('keyUsage'.encode('utf-8'),
                                        True,
                                        'nonRepudiation, digitalSignature, keyEncipherment'.encode('utf-8')),
        OpenSSL.crypto.X509Extension('subjectAltName'.encode('utf-8'),
                                        True,
                                        create_subj_alt_name_list().encode('utf-8'))
    ])

    server_cert.set_issuer(root_ca_cert.get_subject())
    server_cert.set_pubkey(server_key)
    server_cert.sign(root_ca_key, 'sha256')

    with open(server_cert_file.resolve(), "wt") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, server_cert).decode("utf-8"))
        print(f"server cert saved to: {server_cert_file.resolve()}")
    with open(server_key_file.resolve(), "wt") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, server_key).decode("utf-8"))
        print(f"server key saved to: {server_key_file.resolve()}")
    return server_cert_file, server_key_file


def create_ssl_context(server_crt: Path, server_key: Path):
    """Create SSL context for server"""

    def debug_callback(conn, direction, version, content_type, msg_type, data):
        # print("SSL debug:", direction, version, content_type, msg_type, data)
        pass

    # create context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context._msg_callback = debug_callback
    ssl_context.load_cert_chain(certfile=server_crt.resolve(), keyfile=server_key.resolve())
    return ssl_context


async def main(port: int = 9999):
    """Main function"""
    root_ca_cert, root_ca_key = load_root_certificate()
    server_crt, server_key = generate_ip_cert(root_ca_cert, root_ca_key)
    ssl_context = create_ssl_context(server_crt, server_key)

    async def connection_handler(websocket):
        while True:
            try:
                msg = await websocket.recv()
                print(f"<<< {msg}")
                msg = f">>> {msg}"
                await websocket.send(msg)
                print(f"{msg}")
            except (websockets.ConnectionClosed,
                    websockets.ConnectionClosedError,
                    websockets.ConnectionClosedOK):
                print("connection closed")
                return

    print(f"Server: starting on port {port}")
    async with websockets.serve(connection_handler, "0.0.0.0", port, ssl=ssl_context):
        await asyncio.Future()  # run forever

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server: stopped by user")