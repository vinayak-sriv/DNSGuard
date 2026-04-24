# DNSGuard

DNSGuard is a Python-based DNS tunneling detection project. It can analyze saved PCAP files, monitor live DNS traffic, score suspicious queries, and show the results in a local Flask dashboard.

> 3rd Year Project - B.Tech Computer Science & Engineering  
> Vinayak Srivastava  
> Supervised by Dr. Richa Kumari

## What It Does

DNS tunneling hides data inside DNS queries. Instead of looking for one fixed signature, DNSGuard scores DNS traffic using:

- rule-based indicators such as long subdomains, high entropy, frequent queries, and TXT/NULL/MX usage
- an Isolation Forest anomaly model trained on the current capture/session
- per-source behavioral features, so repeated suspicious activity from one IP becomes visible
- a dashboard that makes the results easier to inspect and explain

The project has three main scripts:

| File | Purpose |
| --- | --- |
| `pcap_detector.py` | Core detector for offline PCAP analysis and live DNS capture |
| `dashboard.py` | Local Flask dashboard for PCAP upload, alerts, host summaries, and live events |
| `generate.py` | Synthetic DNS traffic generator for demos and testing |

## Features

- Offline PCAP analysis with CSV output
- Live DNS packet capture with Scapy
- Real-time dashboard updates through `POST /live/push`
- Searchable alert table and per-host summaries
- Tunnel source registry with sample queries and reasons
- Synthetic traffic modes for normal, mixed, tunnel-only, burst, and escalation demos

## Repository Structure

```text
DNSGuard/
├── README.md
├── requirements.txt
├── .gitignore
├── pcap_detector.py
├── dashboard.py
├── generate.py
└── samples/
    ├── dns_tunneling_demo.pcap
    ├── dns_tunneling_demo_results.csv
    ├── dns_test_2600_packets.pcap
    └── dns_test_2600_packets_results.csv
```

## Requirements

- Python 3.10 or newer
- `pip`
- Administrator/root privileges for live packet capture or packet generation

Install dependencies:

```bash
pip install -r requirements.txt
```

The project uses:

```text
flask
numpy
pandas
requests
scapy
scikit-learn
```

Desktop notifications are optional. If you want them, install:

```bash
pip install plyer
```

## Quick Start

Analyze the included sample PCAP:

```bash
python pcap_detector.py samples/dns_tunneling_demo.pcap --no-dashboard --no-notify
```

Start the dashboard:

```bash
python dashboard.py
```

Open:

```text
http://127.0.0.1:8080
```

You can upload a PCAP from the dashboard or run the detector separately and push results to it.

## Usage

### Offline PCAP Analysis

Use this mode when you already have a `.pcap` file from Wireshark, tcpdump, or the sample folder.

```bash
python pcap_detector.py capture.pcap
python pcap_detector.py samples/dns_tunneling_demo.pcap
python pcap_detector.py capture.pcap --no-notify
```

The detector prints a console report and saves a CSV file next to the capture:

```text
capture_results.csv
```

To push offline results to a running dashboard:

```bash
python dashboard.py
python pcap_detector.py capture.pcap --dashboard http://127.0.0.1:8080
```

### Live Capture

Live capture reads packets from a network interface and usually requires elevated privileges.

```bash
sudo python pcap_detector.py --live
sudo python pcap_detector.py --live --iface eth0
sudo python pcap_detector.py --live --iface eth0 --window 120
sudo python pcap_detector.py --live --iface eth0 --no-dashboard
sudo python pcap_detector.py --live --iface eth0 --no-notify
```

Important options:

| Option | Default | Description |
| --- | --- | --- |
| `--live` | off | Enable live DNS capture |
| `--iface` | `eth0` | Network interface to sniff |
| `--window` | `300` | Sliding window size in seconds |
| `--dashboard` | `http://127.0.0.1:8080` | Dashboard URL for event streaming |
| `--no-dashboard` | off | Disable dashboard streaming |
| `--no-notify` | off | Disable desktop notifications |

Find your interface name:

```bash
# Linux
ip a

# macOS
ifconfig

# Windows
ipconfig
```

### Dashboard

Run the dashboard:

```bash
python dashboard.py
```

Then open `http://127.0.0.1:8080`.

The dashboard supports:

- PCAP upload and automatic analysis
- overview cards for total queries, tunnels, and risk levels
- searchable alert table
- source-host summaries
- live event feed
- confirmed tunnel registry

For live mode, run the dashboard and detector in separate terminals:

```bash
# Terminal 1
python dashboard.py

# Terminal 2
sudo python pcap_detector.py --live --iface eth0
```

### Traffic Generator

`generate.py` creates synthetic DNS traffic for lab testing. It uses Scapy to craft packets, so it may need administrator/root privileges.

```bash
sudo python generate.py
sudo python generate.py --mode normal --packets 100
sudo python generate.py --mode tunnel --packets 200
sudo python generate.py --mode burst --packets 100 --delay 0.1
sudo python generate.py --mode escalate
```

Traffic modes:

| Mode | Description | Use case |
| --- | --- | --- |
| `mixed` | 40% tunnel-like and 60% normal traffic | General demo |
| `normal` | Benign DNS queries only | Baseline testing |
| `tunnel` | Tunnel-like high-entropy queries only | Sensitivity testing |
| `burst` | Fast queries from one attacker IP | Rate-rule testing |
| `escalate` | Normal, mixed, then burst traffic | End-to-end demo |

## End-to-End Demo

Use three terminals:

```bash
# Terminal 1: dashboard
python dashboard.py
```

```bash
# Terminal 2: live detector
sudo python pcap_detector.py --live --iface lo --dashboard http://127.0.0.1:8080
```

```bash
# Terminal 3: traffic generator
sudo python generate.py --mode escalate
```

Open `http://127.0.0.1:8080` and watch the live feed. If loopback capture does not work on your OS, replace `lo` with an interface Scapy can sniff.

## How Detection Works

DNSGuard extracts lexical and behavioral features from each DNS query.

| Feature | Type | What it measures |
| --- | --- | --- |
| `query_length` | Lexical | Full queried domain length |
| `subdomain_length` | Lexical | Length of labels before the registered domain |
| `subdomain_entropy` | Lexical | Randomness of the payload-like subdomain |
| `hex_ratio` | Lexical | Share of hex characters in the subdomain |
| `digit_ratio` | Lexical | Share of digits in the full query |
| `dot_count` | Lexical | Number of labels in the domain |
| `query_rate_per_min` | Behavioral | Query rate from the source IP |
| `avg_entropy` | Behavioral | Average entropy for the source IP |
| `avg_response` | Behavioral | Average response size for the source IP |
| `special_type_count` | Behavioral | Count of TXT, NULL, and MX queries |

The final score blends rules and anomaly detection:

```text
risk_score = (rule_hits / TOTAL_RULES) * 50 + ml_score * 50
```

Current rule thresholds:

| Rule | Threshold |
| --- | --- |
| Subdomain length | `> 45` characters |
| Subdomain entropy | `> 3.8` |
| Query rate | `> 5` queries/minute |
| Special record count | `> 10` TXT/NULL/MX queries |

Risk levels:

| Level | Score range | Meaning |
| --- | --- | --- |
| Low | 0-30 | Weak or no tunnel signal |
| Medium | 30-60 | Worth reviewing |
| High | 60-100 | Strong suspicious pattern |

Rows with `risk_score >= 50` are labelled `TUNNEL`.

## Dashboard API

The dashboard is local-only by default. Set `DNS_SHIELD_ALLOW_REMOTE=1` only if you intentionally want remote clients to call it.

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | `GET` | Dashboard UI |
| `/analyse` | `POST` | Upload and analyze a PCAP file |
| `/results` | `GET` | Read latest offline analysis results |
| `/live/push` | `POST` | Ingest live detector events |
| `/live/status` | `GET` | Read live feed state |
| `/live/reset` | `POST` | Clear live feed state |

Example PCAP upload:

```bash
curl -X POST http://127.0.0.1:8080/analyse -F "pcap=@capture.pcap"
```

## Example Output

```text
========================================================================
DNS TUNNELING DETECTION REPORT
Generated: 2026-04-24 15:05:46
========================================================================

Traffic Summary
------------------------------------------------------------------------
Total DNS queries analysed : 800
Unique source IPs          : 17
Flagged as TUNNEL          : 266 (33.2%)
High risk queries          : 192
Medium risk queries        : 188
Low risk queries           : 420

Per-IP Summary
------------------------------------------------------------------------
IP                Queries  Max Risk  Avg Risk  Tunnels
----------------- ------- --------- --------- --------
10.0.0.77             150      87.5      68.3      150  *** SUSPECTED TUNNEL SOURCE ***
10.0.0.42             150      86.0      59.1      116  *** SUSPECTED TUNNEL SOURCE ***
```

CSV output includes:

```text
ts, src_ip, dst_ip, sport, query, record_type, response_size,
subdomain_length, subdomain_entropy, hex_ratio, query_rate_per_min,
risk_score, risk_level, prediction
```

## Limitations

- DNS-over-HTTPS and DNS-over-TLS are not visible to this parser unless decrypted upstream.
- The raw parser focuses on IPv4 UDP DNS traffic.
- Small captures provide less behavioral context for anomaly scoring.
- Attackers can reduce entropy by padding payloads with dictionary-like labels.
- The synthetic generator is for lab validation, not a replacement for real network baselines.

## References

1. Farnham, G. and Atlasis, A. - *Detecting DNS Tunneling.* SANS Institute InfoSec Reading Room, 2013.  
   https://www.sans.org/white-papers/34152/

2. Ellens, W. et al. - *Flow-based Detection of DNS Tunnels.* Lecture Notes in Computer Science, 2013.  
   https://link.springer.com/chapter/10.1007/978-3-642-40973-7_11

3. Homem, I., Papapetrou, P. and Dosis, S. - *Information-Entropy-Based DNS Tunnel Prediction.* IFIP AICT, 2018.  
   https://link.springer.com/chapter/10.1007/978-3-319-99277-8_8

4. Liu, F.T., Ting, K.M. and Zhou, Z.-H. - *Isolation Forest.* IEEE ICDM, 2008.  
   https://ieeexplore.ieee.org/document/4781136/

5. iodine - IP-over-DNS tunnel.  
   https://github.com/yarrick/iodine

6. DNScat2 - DNS-based command-and-control framework.  
   https://github.com/iagox86/dnscat2

7. Zeek Network Security Monitor.  
   https://zeek.org

## Authors

DNSGuard was developed as a B.Tech CSE final year project by Vinayak Srivastava under the supervision of Dr. Richa Kumari at UPES Dehradun.
