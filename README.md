# veryDisco

Network device & protocol analyzer. Feed it a pcap file and get a breakdown of every device on the network and the protocols they speak.

## Features

- **Device discovery** — identifies devices by MAC address, maps IPs, and lists all observed protocols
- **DNS query log** — shows which domains each device is resolving
- **Conversation map** — source → destination pairs ranked by traffic volume
- **Cleartext traffic warnings** — flags unencrypted protocols (HTTP, Telnet, FTP, MQTT, etc.)
- **Dual output** — terminal report + dark-themed HTML report
- **Neo4j integration** — export to Cypher file or write directly to a Neo4j graph database (all nodes tagged `:Pcap` for selective management)

## Quick start

```bash
# Set up
python3 -m venv .venv
source .venv/bin/activate
pip install scapy

# Analyze a pcap
python3 analyze.py path/to/capture.pcap
```

This prints the report to the terminal and writes an HTML report to `<name>.html` alongside the input file.

### Neo4j export

```bash
# 1. Copy & edit the config
cp verydisco.conf.example verydisco.conf

# 2. Generate a Cypher file for review
python3 analyze.py capture.pcap --neo4j
# -> writes capture.cypher

# 3. When happy, push to Neo4j
python3 analyze.py capture.pcap --neo4j-write

# 4. Clear all pcap-imported data from the database
python3 analyze.py --neo4j-clear
```

All imported nodes carry the `:Pcap` label and `source: 'pcap'` property, so they can be deleted independently of data from other sources (e.g. an asset list import).

### Generate test data

```bash
python3 generate_pcap.py
python3 analyze.py capture.pcap
```

`generate_pcap.py` creates a synthetic pcap with 6 simulated devices speaking ARP, DNS, HTTP, HTTPS, SSH, ICMP, ICMPv6, NTP, DHCP, mDNS, and MQTT.

### or real data
```bash
sudo tcpdump -i any -c 1000 -w capture-local.pcap
```

## Output sections

| Section | Description |
|---------|-------------|
| Devices | MAC, IPs, and protocol badges per device |
| DNS Queries | Domains resolved by each source IP |
| Conversations | Traffic pairs with packet count, byte volume, and protocols |
| Cleartext Warnings | Unencrypted traffic that may expose sensitive data |

## Requirements

- Python 3.10+
- [Scapy](https://scapy.net/)
- [neo4j](https://pypi.org/project/neo4j/) (for `--neo4j-write` / `--neo4j-clear`)

## Roadmap

- [x] Graph database integration (Neo4j) for relationship queries
- [ ] TLS SNI extraction
- [ ] GeoIP lookups for external IPs
- [ ] Port scan detection

## License

MIT
