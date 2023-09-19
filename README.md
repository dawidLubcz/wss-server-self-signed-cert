# Secure web socket server with self signed certificate on IP address
Short instruction with code snippets how to set up web socket server (it should works well for https also) with SSL based on self signed certificate on IP address.

## Create root key and certificate
```sh
openssl genrsa -out certs/rootca.key 4096
openssl req -x509 -new -nodes -key certs/rootca.key -sha256 -days 1024 -out certs/rootca.crt
```

### To confirm view certificates
```sh
openssl x509 -in certs/rootca.crt -text -noout
openssl x509 -in certs/server.crt -text -noout
```

## To be able to connect to the server the root certificate has to be added to the system as trusted root certificate authority
* Windows: https://docs.microsoft.com/en-us/skype-sdk/sdn/articles/installing-the-trusted-root-certificate
* Linux: https://ubuntu.com/server/docs/security-trust-store
* Chrome: https://support.google.com/chrome/a/answer/3505249?hl=en
* Android: https://support.google.com/pixelphone/answer/2844832?hl=en
* Ios: https://support.apple.com/en-us/HT204477 / https://kb.mit.edu/confluence/display/mitcontrib/Installing+Root+and+Personal+Certificates+on+iOS


## Run server:
Server will generate self signed cert for host IPs (all network interfaces) using subjectAltName field

```python
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
```

and will be signed by the generated root certificate.

### Run server:
```sh
python3 -m pip install requirements.txt
python3 wss_server.py
```

Example output
```
Using proactor: IocpProactor
Server: root certificate loaded, cert=p:\Projects\Python\wss_self_signed\certs\rootca.crt, key=p:\Projects\Python\wss_self_signed\certs\rootca.key
generate cert for IP
get_host_ip: hostname=DESKTOP-CTM0D2B aliaslist=[] ipaddrlist=['192.168.37.1', '192.168.16.1', '172.18.144.1', '192.168.56.1', '172.18.96.1', '192.168.0.122']
subjectAltName input IP:192.168.37.1,IP:192.168.16.1,IP:172.18.144.1,IP:192.168.56.1,IP:172.18.96.1,IP:192.168.0.122
server cert saved to: P:\Projects\Python\wss_self_signed\certs\server.crt
server key saved to: P:\Projects\Python\wss_self_signed\certs\server.key
Server: starting on port 9999
server listening on 0.0.0.0:9999
```

## Open browser (with imported root ca)
Open debug tools and paste js snippet:

```js
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
```

#### Replace {host IP} with correct host ip and press ENTER.
You should see message received from the server in browser window
```
WebSocket {url: 'wss://192.168.0.122:9999/', readyState: 0, bufferedAmount: 0, onopen: ƒ, onerror: ƒ, …}
VM27:8 WSS connection has been opened.
VM27:15 Received a message: >>> Hello, this is the WSS client!
```
And log on the server side:
```
< TEXT 'Hello, this is the WSS client!' [30 bytes]
<<< Hello, this is the WSS client!
> TEXT '>>> Hello, this is the WSS client!' [34 bytes]
>>> Hello, this is the WSS client!
```

### Thats all!
