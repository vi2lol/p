import asyncio
import aiohttp
import aiodns
import socket
import ipaddress
from ipwhois import IPWhois

CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

TARGET_PORTS = [80, 443, 8080]

def is_cloudflare_ip(ip):
    ip_addr = ipaddress.ip_address(ip)
    return any(ip_addr in ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IP_RANGES)

async def resolve_dns(subdomain, resolver):
    try:
        result = await resolver.gethostbyname(subdomain, socket.AF_INET)
        return subdomain, result.addresses[0]
    except:
        return subdomain, None

def lookup_asn(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        asn = results.get("asn")
        org = results.get("network", {}).get("name", "")
        return asn, org
    except:
        return None, None

async def check_http(ip, port):
    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(url, timeout=4, allow_redirects=True) as resp:
                server = resp.headers.get("Server", "-")
                title = ""
                try:
                    text = await resp.text()
                    start = text.lower().find("<title>")
                    end = text.lower().find("</title>")
                    if start != -1 and end != -1:
                        title = text[start + 7:end].strip()
                except:
                    pass
                return port, resp.status, server, title, str(resp.url)
    except:
        return port, None, None, None, None

async def main(domain, wordlist_path):
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]
    subdomains = [f"{w}.{domain}" for w in words]

    resolver = aiodns.DNSResolver()
    tasks = [resolve_dns(sub, resolver) for sub in subdomains]
    resolved = await asyncio.gather(*tasks)

    found = []
    for sub, ip in resolved:
        if ip and not is_cloudflare_ip(ip):
            found.append((sub, ip))

    if not found:
        print("Tidak ditemukan origin IP di luar jaringan Cloudflare")
        return

    for sub, ip in found:
        print(f"\nSubdomain: {sub}")
        print(f"IP: {ip}")
        asn, org = lookup_asn(ip)
        print(f"ASN: {asn or '-'} | Org: {org or '-'}")

        port_tasks = [check_http(ip, port) for port in TARGET_PORTS]
        results = await asyncio.gather(*port_tasks)
        for port, status, server, title, final_url in results:
            if status:
                print(f"Port {port} terbuka | Status: {status} | Server: {server or '-'} | Title: {title or '-'} | URL: {final_url or '-'}")
            else:
                print(f"Port {port} tertutup atau tidak merespons")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python extreme_bypass.py <domain> <wordlist.txt>")
    else:
        asyncio.run(main(sys.argv[1], sys.argv[2]))
