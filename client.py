import requests, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

BASE = "http://localhost:8000"

client_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public = client_private.public_key()

def client_pub_pem():
    return client_public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

print("=== Сценарий 1: подпись на стороне клиента ===")

message = "Hi, server! This is a message from the client."
print(f"message: {message}")

signature = client_private.sign(
    message.encode(),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

resp = requests.post(BASE + "/verify", json={
    "message": message,
    "signature": base64.b64encode(signature).decode(),
    "public_key": client_pub_pem()
})

if resp.status_code != 200:
    print(f"Ошибка от сервера: {resp.status_code} {resp.text}")
    exit(1)

result = resp.json()
print(f"Результат верификации: {'✓ Подпись верна' if result['valid'] else '✗ Подпись недействительна'}\n")

# --- Сценарий 2: подпись на стороне сервера ---
print("=== Сценарий 2: подпись на стороне сервера ===")

resp = requests.get(BASE + "/public-key")
if resp.status_code != 200:
    print(f"Ошибка от сервера: {resp.status_code} {resp.text}")
    exit(1)

server_pub_pem = resp.json()["public_key"]
server_public = serialization.load_pem_public_key(server_pub_pem.encode())
print("Публичный ключ сервера получен.")

resp = requests.get(BASE + "/sign-message")
if resp.status_code != 200:
    print(f"Ошибка от сервера: {resp.status_code} {resp.text}")
    exit(1)

data = resp.json()
message = data["message"]
signature = base64.b64decode(data["signature"])
print(f"Сообщение от сервера: {message}")

try:
    server_public.verify(
        signature, message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    print("Результат верификации: ✓ Подпись верна")
except InvalidSignature:
    print("Результат верификации: ✗ Подпись недействительна")
