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
pip install scapy python-nmap manuf neo4j

# Analyze a pcap
python3 analyze.py path/to/capture.pcap
```

This prints the report to the terminal and writes an HTML report to `<name>.html` alongside the input file.

### Nmap active scanning

The `--nmap` flag runs an active nmap scan (`-O -sV`) against the IPs discovered in the pcap to detect OS and open ports/services. This requires **sudo** because OS fingerprinting needs raw sockets.

On macOS, run it from Terminal (not inside an IDE terminal, which may not pass sudo correctly):

```bash
sudo python3 analyze.py capture-local.pcap --nmap
```

You can also combine it with the Neo4j flags:

```bash
sudo python3 analyze.py capture-local.pcap --nmap --neo4j
sudo python3 analyze.py capture-local.pcap --nmap --neo4j-write
```

Detected open ports and services are stored as `open_ports` on the IPAddress nodes in Neo4j.

### Neo4j integration

#### 1. Configure

Copy the example config and fill in your Neo4j credentials:

```bash
cp verydisco.conf.example verydisco.conf
```

Edit `verydisco.conf`:

```ini
[neo4j]
uri = bolt://localhost:7687
username = neo4j
password = your_password
database = neo4j
```

#### 2. Generate Cypher file for review

```bash
python3 analyze.py capture.pcap --neo4j
# -> writes capture.cypher
```

Review the `.cypher` file to verify the data looks correct before importing.

#### 3. Write to Neo4j

```bash
python3 analyze.py capture.pcap --neo4j-write
```

This generates the Cypher and executes it directly against your Neo4j instance.

#### 4. Clear pcap data from Neo4j

```bash
python3 analyze.py --neo4j-clear
```

This deletes **only** nodes with the `:Pcap` label (and their relationships), leaving any other data in the database untouched. Useful for re-importing after a new scan or when cleaning up.

You can combine clear + write in one go:

```bash
python3 analyze.py capture.pcap --neo4j-clear --neo4j-write
```

#### Graph data model

- **(:Device:Pcap)** — keyed by MAC or IP, with `vendor`, `os_guess`, `protocols`
- **(:IPAddress:Pcap)** — `address`, `scope`, `open_ports` (from nmap)
- **(:IPAddress:Pcap:External)** — public IPs get an extra `:External` label
- **(:Domain:Pcap)** — DNS domain names
- `(:Device)-[:HAS_IP]->(:IPAddress)`
- `(:IPAddress)-[:COMMUNICATES_WITH {packets, bytes, protocols, ports}]->(:IPAddress)`
- `(:IPAddress)-[:QUERIES {count}]->(:Domain)`
- `(:IPAddress)-[:HAS_CLEARTEXT_WARNING {proto, port}]->(:IPAddress)`

### Generate test data

```bash
python3 generate_pcap.py
python3 analyze.py capture.pcap
```

`generate_pcap.py` creates a synthetic pcap with 6 simulated devices speaking ARP, DNS, HTTP, HTTPS, SSH, ICMP, ICMPv6, NTP, DHCP, mDNS, and MQTT.

### Capture real traffic

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
- [python-nmap](https://pypi.org/project/python-nmap/) + nmap installed (`brew install nmap` on macOS)
- [manuf](https://pypi.org/project/manuf/) — MAC vendor lookups
- [neo4j](https://pypi.org/project/neo4j/) (for `--neo4j-write` / `--neo4j-clear`)

## Roadmap

- [x] Graph database integration (Neo4j) for relationship queries
- [ ] TLS SNI extraction
- [ ] GeoIP lookups for external IPs
- [ ] Port scan detection

## License

MIT
