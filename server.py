"""Digital signature server implementing two EDS scenarios."""

import base64
import random
import string

import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from pydantic import BaseModel
from rich.console import Console


app = FastAPI()
console = Console()

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()


def _get_public_key_pem() -> str:
    """Returns the server's public key in PEM format."""
    return _public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _sign(message: bytes) -> bytes:
    """Signs a message with the server's private key."""
    return _private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def _verify(signature: bytes, message: bytes, public_key) -> bool:
    """Verifies a signature against a message and public key."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


class VerifyRequest(BaseModel):
    message: str
    signature: str
    public_key: str


# Scenario 2, step 1
@app.get("/public-key")
def get_public_key():
    """Returns the server's public key."""
    console.log("[cyan]GET[/cyan] /public-key")
    
    return {"public_key": _get_public_key_pem()}


# Scenario 2, steps 2-4
@app.get("/sign-message")
def sign_message():
    """Generates a random message and signs it with the server's private key."""
    console.log("[cyan]GET[/cyan] /sign-message")
    
    message = (
        "".join(random.choices(string.ascii_letters + " ", k=40))
        + " (signed by server)"
    )
    
    signature = _sign(message.encode())
    
    console.log(f"  Message   : [yellow]{message}[/yellow]")
    console.log("  Signature : [green]created[/green]")
    
    return {
        "message": message,
        "signature": base64.b64encode(signature).decode(),
    }


# Scenario 1, steps 4-5
@app.post("/verify")
def verify(req: VerifyRequest):
    """Verifies a client's message signature using the provided public key."""
    console.log("[cyan]POST[/cyan] /verify")
    
    message = req.message.encode()
    signature = base64.b64decode(req.signature)
    client_pub = serialization.load_pem_public_key(req.public_key.encode())

    valid = _verify(signature, message, client_pub)
    
    console.log(f"  Message    : [yellow]{req.message}[/yellow]")
    
    if valid:
        console.log("  Signature  : [green]✓ Valid[/green]")
    else:
        console.log("  Signature  : [red]✗ Invalid[/red]")
        
    return {"valid": valid}


if __name__ == "__main__":
    console.rule("[bold green]EDS Server")
    uvicorn.run(app, host="localhost", port=8000)
