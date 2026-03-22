#!/usr/bin/env python3
"""Analyze a pcap file and list all devices with the protocols they speak."""

import argparse
import html
import ipaddress
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import nmap
from manuf import manuf as manuf_mod
from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, ICMP, IPv6, rdpcap, CookedLinux

# Well-known port -> protocol name mapping
PORT_NAMES = {
    22: "SSH",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    123: "NTP",
    443: "HTTPS/TLS",
    853: "DNS-over-TLS",
    1883: "MQTT",
    3306: "MySQL",
    5353: "mDNS",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8883: "MQTT-TLS",
}

# Ports that carry unencrypted / cleartext protocols
CLEARTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    1883: "MQTT",
    8080: "HTTP-alt",
}


def protocol_label(port: int) -> str | None:
    """Return a protocol label with port number, e.g. 'SSH (22)'."""
    name = PORT_NAMES.get(port)
    return f"{name} ({port})" if name else None


def protocol_base_name(label: str) -> str:
    """Strip the port suffix: 'SSH (22)' -> 'SSH'."""
    return label.split(" (")[0] if " (" in label else label


# ── Helpers ───────────────────────────────────────────────────────

_mac_parser = manuf_mod.MacParser()


def mac_vendor(mac: str) -> str | None:
    """Look up the vendor/manufacturer for a MAC address."""
    try:
        long = _mac_parser.get_manuf_long(mac)
        return long or _mac_parser.get_manuf(mac) or None
    except Exception:
        return None


def is_private_ip(addr: str) -> bool:
    """Return True if *addr* is an RFC-1918 / link-local / loopback address."""
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def ip_scope(addr: str) -> str:
    """Return 'private', 'public', or 'special' for an IP address."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    return "public"


def guess_os_from_ttl(ttl: int) -> str:
    """Guess the OS family from the initial TTL value."""
    if ttl <= 0:
        return "unknown"
    # Round up to nearest common initial TTL
    if ttl <= 32:
        return "unknown"
    if ttl <= 64:
        return "Linux/macOS"   # initial TTL 64
    if ttl <= 128:
        return "Windows"       # initial TTL 128
    return "network device"    # initial TTL 255 (routers, switches)


# ── Data structures ──────────────────────────────────────────────

@dataclass
class DeviceInfo:
    ips: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    vendor: str | None = None
    os_guess: str | None = None
    ttl_samples: list[int] = field(default_factory=list)
    # Populated by nmap active scan
    nmap_os: str | None = None
    nmap_services: list[str] = field(default_factory=list)  # e.g. ["22/tcp ssh OpenSSH 8.9"]


@dataclass
class ConversationInfo:
    packets: int = 0
    bytes: int = 0
    protocols: set[str] = field(default_factory=set)


@dataclass
class CleartextWarning:
    src: str
    dst: str
    proto: str
    port: int


@dataclass
class AnalysisResult:
    pcap_path: str
    total_packets: int
    devices: dict[str, DeviceInfo]
    dns_queries: dict[str, list[str]]
    conversations: dict[tuple[str, str], ConversationInfo]
    cleartext_warnings: list[CleartextWarning]


# ── Extraction ───────────────────────────────────────────────────

def extract(pcap_path: str) -> AnalysisResult:
    """Parse a pcap and return structured analysis data."""
    packets = rdpcap(pcap_path)

    devices: dict[str, DeviceInfo] = defaultdict(DeviceInfo)
    dns_queries: dict[str, list[str]] = defaultdict(list)
    conversations: dict[tuple[str, str], ConversationInfo] = defaultdict(ConversationInfo)
    cleartext_warnings: list[CleartextWarning] = []

    for pkt in packets:
        # Determine device key: MAC when available, else source IP.
        has_ether = pkt.haslayer(Ether)
        has_sll = pkt.haslayer(CookedLinux)

        if has_ether:
            device_key = pkt[Ether].src
        else:
            # CookedLinux / raw IP — no MAC; will key by IP below.
            device_key = None

        # --- ARP (Ethernet only) ---
        if has_ether and pkt.haslayer(ARP):
            arp = pkt[ARP]
            devices[device_key].protocols.add("ARP")
            if arp.psrc and arp.psrc != "0.0.0.0":
                devices[device_key].ips.add(arp.psrc)
            continue

        # --- IPv6 ---
        if pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            if device_key is None:
                device_key = ipv6.src
            devices[device_key].ips.add(ipv6.src)
            devices[device_key].protocols.add("IPv6")
            if pkt.haslayer("ICMPv6EchoRequest") or pkt.haslayer("ICMPv6EchoReply"):
                devices[device_key].protocols.add("ICMPv6")
            continue

        # --- IPv4 ---
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        if device_key is None:
            device_key = src_ip
        devices[device_key].ips.add(src_ip)

        # Collect TTL for OS fingerprinting
        devices[device_key].ttl_samples.append(ip_layer.ttl)

        pair = (src_ip, dst_ip)
        conversations[pair].packets += 1
        conversations[pair].bytes += len(pkt)

        # DNS
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode(errors="replace")
            qname = qname.rstrip(".")
            if qname:
                dns_queries[src_ip].append(qname)

        # ICMP
        if pkt.haslayer(ICMP):
            devices[device_key].protocols.add("ICMP")
            conversations[pair].protocols.add("ICMP")
            continue

        # TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            devices[device_key].protocols.add("TCP")
            for port in (tcp.sport, tcp.dport):
                label = protocol_label(port)
                if label:
                    devices[device_key].protocols.add(label)
                    conversations[pair].protocols.add(label)
                ct_name = CLEARTEXT_PORTS.get(port)
                if ct_name:
                    cleartext_warnings.append(CleartextWarning(src_ip, dst_ip, ct_name, port))

        # UDP
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            devices[device_key].protocols.add("UDP")
            for port in (udp.sport, udp.dport):
                label = protocol_label(port)
                if label:
                    devices[device_key].protocols.add(label)
                    conversations[pair].protocols.add(label)

    # ── Post-processing ──
    for key, dev in devices.items():
        # MAC vendor lookup
        is_mac = len(key) == 17 and key.count(":") == 5
        if is_mac:
            dev.vendor = mac_vendor(key)

        # OS fingerprint from TTL
        if dev.ttl_samples:
            # Use the max observed TTL (closest to initial value)
            best_ttl = max(dev.ttl_samples)
            dev.os_guess = guess_os_from_ttl(best_ttl)

    return AnalysisResult(
        pcap_path=pcap_path,
        total_packets=len(packets),
        devices=dict(devices),
        dns_queries=dict(dns_queries),
        conversations=dict(conversations),
        cleartext_warnings=cleartext_warnings,
    )


# ── Nmap active scanning ─────────────────────────────────────────

def _scannable_ips(result: AnalysisResult) -> list[str]:
    """Return deduplicated private/non-special IPs worth scanning."""
    seen: set[str] = set()
    for dev in result.devices.values():
        for addr in dev.ips:
            if addr in seen:
                continue
            scope = ip_scope(addr)
            if scope in ("private", "public"):
                seen.add(addr)
    return sorted(seen)


def run_nmap_scan(result: AnalysisResult) -> None:
    """Run nmap -O -sV against discovered IPs and enrich device data."""
    if not shutil.which("nmap"):
        print("  [!] nmap not found in PATH, skipping active scan.")
        return

    targets = _scannable_ips(result)
    if not targets:
        print("  [!] No scannable IPs found, skipping nmap.")
        return

    target_str = " ".join(targets)
    print(f"\n  [nmap] Scanning {len(targets)} host(s): {target_str}")
    print(f"  [nmap] This requires sudo for OS detection (-O).")
    print(f"  [nmap] Running: sudo nmap -O -sV --top-ports 100 {target_str}")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_str, arguments="-O -sV --top-ports 100", sudo=True)
    except nmap.PortScannerError as e:
        print(f"  [!] nmap error: {e}")
        return

    # Build IP -> device_key lookup
    ip_to_key: dict[str, str] = {}
    for key, dev in result.devices.items():
        for addr in dev.ips:
            ip_to_key[addr] = key

    for host in nm.all_hosts():
        device_key = ip_to_key.get(host)
        if device_key is None:
            continue
        dev = result.devices[device_key]

        # OS detection
        if "osmatch" in nm[host]:
            matches = nm[host]["osmatch"]
            if matches:
                best = matches[0]
                dev.nmap_os = f"{best['name']} ({best['accuracy']}%)"

        # Service/version detection
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                svc = nm[host][proto][port]
                state = svc.get("state", "")
                if state != "open":
                    continue
                name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                extra = svc.get("extrainfo", "")
                parts = [s for s in [product, version, extra] if s]
                detail = " ".join(parts)
                line = f"{port}/{proto} {name}"
                if detail:
                    line += f" — {detail}"
                dev.nmap_services.append(line)

    print(f"  [nmap] Scan complete.")


# ── Terminal output ──────────────────────────────────────────────

def print_report(r: AnalysisResult) -> None:
    print(f"\n{'=' * 64}")
    print(f"  veryDisco \u2014 Network Device & Protocol Analyzer")
    print(f"  Pcap: {r.pcap_path}  |  Packets: {r.total_packets}")
    print(f"{'=' * 64}")

    # Devices
    print(f"\n  [ DEVICES ]")
    sorted_devices = sorted(r.devices.items(), key=lambda d: len(d[1].protocols), reverse=True)
    for i, (key, info) in enumerate(sorted_devices, 1):
        ip_parts = []
        for addr in sorted(info.ips):
            scope = ip_scope(addr)
            ip_parts.append(f"{addr} ({scope})")
        ips_str = ", ".join(ip_parts) or "(no IP)"
        protos = ", ".join(sorted(info.protocols))
        is_mac = len(key) == 17 and key.count(":") == 5
        print(f"\n  Device {i}")
        if is_mac:
            vendor = info.vendor or "unknown"
            print(f"    MAC:       {key}  [{vendor}]")
            print(f"    IP(s):     {ips_str}")
        else:
            print(f"    IP:        {ips_str}")
        if info.nmap_os:
            print(f"    OS (nmap): {info.nmap_os}")
        elif info.os_guess:
            print(f"    OS (TTL):  {info.os_guess}")
        if info.nmap_services:
            print(f"    Services:")
            for svc in info.nmap_services:
                print(f"      - {svc}")
        print(f"    Protocols: {protos}")
    print(f"\n  Total devices: {len(r.devices)}")

    # DNS
    print(f"\n{'=' * 64}")
    print(f"  [ DNS QUERIES ]")
    if r.dns_queries:
        for src_ip, domains in sorted(r.dns_queries.items()):
            unique = Counter(domains)
            print(f"\n  {src_ip}")
            for domain, count in unique.most_common():
                tag = f" (x{count})" if count > 1 else ""
                print(f"    -> {domain}{tag}")
    else:
        print("\n  (none found)")

    # Conversations
    print(f"\n{'=' * 64}")
    print(f"  [ CONVERSATIONS ]")
    sorted_convos = sorted(r.conversations.items(), key=lambda c: c[1].bytes, reverse=True)
    for (src, dst), info in sorted_convos:
        protos = ", ".join(sorted(info.protocols)) if info.protocols else "\u2014"
        print(f"  {src:>15}  ->  {dst:<15}  "
              f"{info.packets:>3} pkts  {info.bytes:>6} bytes  [{protos}]")

    # Cleartext
    print(f"\n{'=' * 64}")
    print(f"  [ CLEARTEXT / UNENCRYPTED TRAFFIC WARNINGS ]")
    if r.cleartext_warnings:
        seen = set()
        for w in r.cleartext_warnings:
            key = (w.src, w.dst, w.proto)
            if key in seen:
                continue
            seen.add(key)
            print(f"  \u26a0  {w.src} -> {w.dst}  [{w.proto} port {w.port}]")
    else:
        print("\n  \u2713 No cleartext traffic detected.")

    print(f"\n{'=' * 64}")


# ── HTML output ──────────────────────────────────────────────────

def _h(text: str) -> str:
    """HTML-escape helper."""
    return html.escape(str(text))


def _proto_badge(proto: str) -> str:
    """Return an HTML badge <span> for a protocol name."""
    color_map = {
        "HTTP": "#e74c3c", "HTTPS/TLS": "#27ae60", "DNS": "#2980b9",
        "SSH": "#8e44ad", "ICMP": "#f39c12", "ICMPv6": "#f39c12",
        "ARP": "#95a5a6", "DHCP": "#1abc9c", "NTP": "#d35400",
        "MQTT": "#e67e22", "mDNS": "#2980b9", "IPv6": "#7f8c8d",
        "TCP": "#34495e", "UDP": "#34495e",
    }
    base = protocol_base_name(proto)
    bg = color_map.get(base, "#636e72")
    return f'<span class="badge" style="background:{bg}">{_h(proto)}</span>'


def generate_html(r: AnalysisResult, output_path: str) -> None:
    sorted_devices = sorted(r.devices.items(), key=lambda d: len(d[1].protocols), reverse=True)
    sorted_convos = sorted(r.conversations.items(), key=lambda c: c[1].bytes, reverse=True)

    # De-duplicate cleartext warnings
    seen_ct: set[tuple] = set()
    unique_warnings: list[CleartextWarning] = []
    for w in r.cleartext_warnings:
        key = (w.src, w.dst, w.proto)
        if key not in seen_ct:
            seen_ct.add(key)
            unique_warnings.append(w)

    # Build HTML
    parts: list[str] = []
    p = parts.append

    p("<!DOCTYPE html>")
    p("<html lang='en'>")
    p("<head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    p("<title>veryDisco &mdash; Report</title>")
    p("<style>")
    p(":root{--bg:#0f1117;--card:#1a1d27;--border:#2a2d3a;--text:#e0e0e0;--dim:#888;--accent:#6c5ce7;}")
    p("*{margin:0;padding:0;box-sizing:border-box}")
    p("body{font-family:'SF Mono',Menlo,Consolas,monospace;background:var(--bg);color:var(--text);padding:2rem}")
    p("h1{color:var(--accent);font-size:1.6rem;margin-bottom:.2rem}")
    p(".subtitle{color:var(--dim);font-size:.85rem;margin-bottom:2rem}")
    p("h2{color:var(--accent);font-size:1.1rem;margin:2rem 0 1rem;border-bottom:1px solid var(--border);padding-bottom:.4rem}")
    p(".card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.2rem;margin-bottom:.8rem}")
    p(".card-title{font-weight:700;margin-bottom:.4rem}")
    p(".label{color:var(--dim);display:inline-block;width:6rem;font-size:.82rem}")
    p(".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;color:#fff;margin:1px 2px}")
    p("table{width:100%;border-collapse:collapse;font-size:.85rem}")
    p("th{text-align:left;color:var(--dim);font-weight:600;padding:.5rem .6rem;border-bottom:1px solid var(--border)}")
    p("td{padding:.45rem .6rem;border-bottom:1px solid var(--border)}")
    p("tr:hover td{background:#22253a}")
    p(".warn{color:#e74c3c;font-weight:700}")
    p(".ok{color:#27ae60}")
    p(".dns-domain{color:#56b6c2}")
    p(".dns-count{color:var(--dim);font-size:.8rem}")
    p(".right{text-align:right}")
    p(".arrow{color:var(--dim)}")
    p("</style></head><body>")

    p("<h1>veryDisco</h1>")
    p(f'<div class="subtitle">{_h(r.pcap_path)} &middot; {r.total_packets} packets</div>')

    # ── Devices ──
    p("<h2>Devices</h2>")
    for i, (key, info) in enumerate(sorted_devices, 1):
        badges = " ".join(_proto_badge(pr) for pr in sorted(info.protocols))
        is_mac = len(key) == 17 and key.count(":") == 5
        # Build IP list with scope badges
        ip_html_parts = []
        for addr in sorted(info.ips):
            scope = ip_scope(addr)
            scope_color = "#e74c3c" if scope == "public" else "#27ae60" if scope == "private" else "#f39c12"
            ip_html_parts.append(f'{_h(addr)} <span class="badge" style="background:{scope_color};font-size:.65rem">{scope}</span>')
        ips_html = ", ".join(ip_html_parts) or "(no IP)"

        p('<div class="card">')
        p(f'<div class="card-title">Device {i}</div>')
        if is_mac:
            vendor = _h(info.vendor) if info.vendor else '<span style="color:var(--dim)">unknown</span>'
            p(f'<div><span class="label">MAC</span>{_h(key)}</div>')
            p(f'<div><span class="label">Vendor</span>{vendor}</div>')
            p(f'<div><span class="label">IP(s)</span>{ips_html}</div>')
        else:
            p(f'<div><span class="label">IP</span>{ips_html}</div>')
        if info.nmap_os:
            p(f'<div><span class="label">OS (nmap)</span>{_h(info.nmap_os)}</div>')
        elif info.os_guess:
            p(f'<div><span class="label">OS (TTL)</span>{_h(info.os_guess)}</div>')
        if info.nmap_services:
            p('<div style="margin-top:.3rem"><span class="label">Services</span></div>')
            p('<ul style="margin:.2rem 0 0 6.5rem;font-size:.82rem;color:var(--dim);list-style:none">')
            for svc in info.nmap_services:
                p(f'<li>{_h(svc)}</li>')
            p('</ul>')
        p(f'<div style="margin-top:.3rem">{badges}</div>')
        p("</div>")
    p(f'<div style="color:var(--dim);margin-top:.4rem">{len(r.devices)} devices total</div>')

    # ── DNS ──
    p("<h2>DNS Queries</h2>")
    if r.dns_queries:
        p("<table><tr><th>Source IP</th><th>Domain</th><th class='right'>Count</th></tr>")
        for src_ip, domains in sorted(r.dns_queries.items()):
            unique = Counter(domains)
            for domain, count in unique.most_common():
                p(f'<tr><td>{_h(src_ip)}</td><td class="dns-domain">{_h(domain)}</td>'
                  f'<td class="right">{count}</td></tr>')
        p("</table>")
    else:
        p('<div style="color:var(--dim)">No DNS queries found.</div>')

    # ── Conversations ──
    p("<h2>Conversations</h2>")
    p("<table><tr><th>Source</th><th></th><th>Destination</th><th class='right'>Packets</th>"
      "<th class='right'>Bytes</th><th>Protocols</th></tr>")
    for (src, dst), info in sorted_convos:
        protos = " ".join(_proto_badge(pr) for pr in sorted(info.protocols)) if info.protocols else "&mdash;"
        p(f'<tr><td>{_h(src)}</td><td class="arrow">&rarr;</td><td>{_h(dst)}</td>'
          f'<td class="right">{info.packets}</td><td class="right">{info.bytes:,}</td>'
          f'<td>{protos}</td></tr>')
    p("</table>")

    # ── Cleartext ──
    p("<h2>Cleartext / Unencrypted Traffic</h2>")
    if unique_warnings:
        p("<table><tr><th>Source</th><th></th><th>Destination</th><th>Protocol</th><th>Port</th></tr>")
        for w in unique_warnings:
            p(f'<tr><td class="warn">{_h(w.src)}</td><td class="arrow">&rarr;</td>'
              f'<td>{_h(w.dst)}</td><td class="warn">{_h(w.proto)}</td>'
              f'<td>{w.port}</td></tr>')
        p("</table>")
    else:
        p('<div class="ok">&#10003; No cleartext traffic detected.</div>')

    p("</body></html>")

    with open(output_path, "w") as f:
        f.write("\n".join(parts))
    print(f"  HTML report written to {output_path}")


# ── Main ─────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="veryDisco",
        description="Network device & protocol analyzer",
    )
    parser.add_argument("pcap", nargs="?", default="capture.pcap", help="Path to pcap file")
    parser.add_argument("--nmap", action="store_true", help="Run active nmap scan (-O -sV) on discovered hosts (requires sudo)")
    args = parser.parse_args()

    result = extract(args.pcap)

    if args.nmap:
        run_nmap_scan(result)

    print_report(result)

    html_out = os.path.splitext(args.pcap)[0] + ".html"
    generate_html(result, html_out)


if __name__ == "__main__":
    main()
