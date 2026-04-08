"""Digital signature client demonstrating two EDS scenarios."""

import base64
import sys

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from rich.console import Console
from rich.panel import Panel


BASE_URL = "http://localhost:8000"

console = Console()

_client_private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)
_client_public_key = _client_private_key.public_key()


def _get_client_public_key_pem() -> str:
    """Returns the client's public key in PEM format."""
    return _client_public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _sign(message: bytes) -> bytes:
    """Signs a message with the client's private key."""
    return _client_private_key.sign(
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


def run_scenario_1() -> None:
    """Scenario 1: client signs a message and server verifies it."""
    console.print(Panel("[bold cyan]Scenario 1: Client-side signing[/bold cyan]"))

    message = "Hi, server! This is a message from the client."
    console.print(f"  Message   : [yellow]{message}[/yellow]")

    signature = _sign(message.encode())

    resp = requests.post(
        BASE_URL + "/verify",
        json={
            "message": message,
            "signature": base64.b64encode(signature).decode(),
            "public_key": _get_client_public_key_pem(),
        },
    )

    if resp.status_code != 200:
        console.print(f"  [red]Server error: {resp.status_code} {resp.text}[/red]")
        sys.exit(1)

    valid = resp.json()["valid"]
    if valid:
        console.print("  Signature : [green]✓ Valid[/green]\n")
    else:
        console.print("  Signature : [red]✗ Invalid[/red]\n")


def run_scenario_2() -> None:
    """Scenario 2: server signs a message and client verifies it."""
    console.print(Panel("[bold cyan]Scenario 2: Server-side signing[/bold cyan]"))

    server_pub_pem = requests.get(BASE_URL + "/public-key").json()["public_key"]
    server_public_key = serialization.load_pem_public_key(server_pub_pem.encode())
    console.print("  Server public key : [green]received[/green]")

    data = requests.get(BASE_URL + "/sign-message").json()
    message = data["message"]
    signature = base64.b64decode(data["signature"])
    console.print(f"  Message           : [yellow]{message}[/yellow]")

    valid = _verify(signature, message.encode(), server_public_key)
    if valid:
        console.print("  Signature         : [green]✓ Valid[/green]")
    else:
        console.print("  Signature         : [red]✗ Invalid[/red]")


if __name__ == "__main__":
    run_scenario_1()
    run_scenario_2()
