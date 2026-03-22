#!/usr/bin/env python3
"""Generate a synthetic pcap file with diverse devices and protocols."""

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
    ARP, DNS, DNSQR, Raw, wrpcap,
)

PCAP_PATH = "capture.pcap"

# Simulated devices (MAC, IP)
DEVICES = {
    "laptop":  ("aa:bb:cc:00:00:01", "192.168.1.10"),
    "phone":   ("aa:bb:cc:00:00:02", "192.168.1.11"),
    "server":  ("aa:bb:cc:00:00:03", "10.0.0.5"),
    "printer": ("aa:bb:cc:00:00:04", "192.168.1.50"),
    "iot_cam": ("aa:bb:cc:00:00:05", "192.168.1.60"),
    "router":  ("aa:bb:cc:00:00:ff", "192.168.1.1"),
}

packets = []

def eth(src, dst="aa:bb:cc:00:00:ff"):
    return Ether(src=src, dst=dst)

# --- ARP: router announces itself ---
packets.append(
    Ether(src=DEVICES["router"][0], dst="ff:ff:ff:ff:ff:ff")
    / ARP(op="is-at", hwsrc=DEVICES["router"][0], psrc=DEVICES["router"][1])
)
# laptop ARP request
packets.append(
    Ether(src=DEVICES["laptop"][0], dst="ff:ff:ff:ff:ff:ff")
    / ARP(op="who-has", hwsrc=DEVICES["laptop"][0], psrc=DEVICES["laptop"][1], pdst="192.168.1.1")
)

# --- DNS queries (UDP/53) ---
for name in ("laptop", "phone", "iot_cam"):
    mac, ip = DEVICES[name]
    packets.append(
        eth(mac)
        / IP(src=ip, dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

# --- HTTP-style TCP (port 80) from laptop ---
mac, ip = DEVICES["laptop"]
packets.append(
    eth(mac)
    / IP(src=ip, dst="93.184.216.34")
    / TCP(sport=50000, dport=80, flags="S")
)
packets.append(
    eth(mac)
    / IP(src=ip, dst="93.184.216.34")
    / TCP(sport=50000, dport=80, flags="A")
    / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
)

# --- HTTPS-style TCP (port 443) from phone ---
mac, ip = DEVICES["phone"]
packets.append(
    eth(mac)
    / IP(src=ip, dst="142.250.80.46")
    / TCP(sport=50100, dport=443, flags="S")
)

# --- SSH (port 22) from laptop to server ---
mac, ip = DEVICES["laptop"]
packets.append(
    eth(mac)
    / IP(src=ip, dst=DEVICES["server"][1])
    / TCP(sport=50200, dport=22, flags="S")
)

# --- ICMP ping from phone to router ---
mac, ip = DEVICES["phone"]
packets.append(
    eth(mac)
    / IP(src=ip, dst=DEVICES["router"][1])
    / ICMP(type="echo-request")
)

# --- NTP (UDP/123) from iot_cam ---
mac, ip = DEVICES["iot_cam"]
packets.append(
    eth(mac)
    / IP(src=ip, dst="129.6.15.28")
    / UDP(sport=12346, dport=123)
    / Raw(load=b"\x1b" + b"\x00" * 47)  # minimal NTP request
)

# --- DHCP-like (UDP/67-68) from printer ---
mac, ip = DEVICES["printer"]
packets.append(
    eth(mac, dst="ff:ff:ff:ff:ff:ff")
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(sport=68, dport=67)
    / Raw(load=b"\x01" * 20)  # simplified DHCP discover
)

# --- mDNS (UDP/5353) from printer ---
packets.append(
    eth(mac, dst="01:00:5e:00:00:fb")
    / IP(src=DEVICES["printer"][1], dst="224.0.0.251")
    / UDP(sport=5353, dport=5353)
    / DNS(rd=0, qd=DNSQR(qname="_ipp._tcp.local", qtype="PTR"))
)

# --- IPv6 ICMPv6 from laptop ---
packets.append(
    Ether(src=DEVICES["laptop"][0], dst="33:33:00:00:00:01")
    / IPv6(src="fe80::1", dst="ff02::1")
    / ICMPv6EchoRequest()
)

# --- MQTT-like (TCP/1883) from iot_cam to server ---
mac, ip = DEVICES["iot_cam"]
packets.append(
    eth(mac)
    / IP(src=ip, dst=DEVICES["server"][1])
    / TCP(sport=50300, dport=1883, flags="S")
)

# --- Extra TCP from server back to laptop (response traffic) ---
packets.append(
    eth(DEVICES["server"][0], dst=DEVICES["laptop"][0])
    / IP(src=DEVICES["server"][1], dst=DEVICES["laptop"][1])
    / TCP(sport=22, dport=50200, flags="SA")
)

wrpcap(PCAP_PATH, packets)
print(f"Wrote {len(packets)} packets to {PCAP_PATH}")
