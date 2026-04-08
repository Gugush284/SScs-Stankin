from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import json, base64, random, string

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def pub_key_pem():
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[server] {format % args}")

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length))

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        
        self.wfile.write(body)

    # Сценарий 2
    def do_GET(self):
        if self.path == "/public-key":
            self.send_json({"public_key": pub_key_pem()})

        elif self.path == "/sign-message":
            message = "".join(random.choices(string.ascii_letters + " ", k=40)) + " (signed by server)"
            print(f"Signing message: {message}")

            signature = private_key.sign(
                message.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            
            self.send_json({
                "message": message,
                "signature": base64.b64encode(signature).decode()
            })
            
        else:
            self.send_json({"error": "not found"}, 404)

    # Сценарий 1
    def do_POST(self):
        if self.path == "/verify":
            data = self.read_json()
            message = data["message"].encode()
            signature = base64.b64decode(data["signature"])
            client_pub = serialization.load_pem_public_key(data["public_key"].encode())
            
            try:
                client_pub.verify(
                    signature, message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                
                self.send_json({"valid": True})
                
                print(f"Message: {message.decode()}")
            except InvalidSignature:
                self.send_json({"valid": False})
                
        else:
            self.send_json({"error": "not found"}, 404)

if __name__ == "__main__":
    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("localhost", 8000), Handler)
    print("Server running on http://localhost:8000")
    server.serve_forever()
