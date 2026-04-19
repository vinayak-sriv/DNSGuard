# DNSGuard 🛡️
### AI-Powered DNS Threat Intelligence & Real-Time Tunneling Detection System

> **Network Security Project — B.Tech Computer Science & Engineering**
> Vinayak Srivastava (500119362) · Sumit Singh Chauhan (500120276)
> Supervised by Dr. Richa Kumari

---

## Table of Contents

- [Overview](#overview)
- [Why DNS Tunneling is Dangerous](#why-dns-tunneling-is-dangerous)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Live Capture Mode](#1-live-capture-mode-pcap_detectorpy)
  - [2. Offline PCAP Analysis](#2-offline-pcap-analysis)
  - [3. Web Dashboard](#3-web-dashboard-dashboardpy)
  - [4. Traffic Simulator](#4-traffic-simulator-generatepy)
- [Dashboard API Reference](#dashboard-api-reference)
- [Detection Methodology](#detection-methodology)
- [Sample Output](#sample-output)
- [Testing the Full Pipeline](#testing-the-full-pipeline)
- [Limitations](#limitations)
- [References](#references)

---

## Overview

**DNSGuard** is a Python-based DNS tunneling detection system that combines rule-based thresholds, unsupervised machine learning (Isolation Forest), and a real-time web dashboard to identify covert data exfiltration and command-and-control traffic hidden inside DNS queries.

DNS tunneling is one of the most persistent attack vectors in enterprise networks because DNS traffic is universally trusted — even strict firewalls allow port 53 outbound. DNSGuard addresses this blind spot with a three-file system:

| File | Role |
|------|------|
| `pcap_detector.py` | Core detection engine — live capture or offline PCAP analysis |
| `dashboard.py` | Flask web dashboard — real-time visualisation at `http://localhost:8080` |
| `generate.py` | Traffic simulator — generates realistic normal + tunnel DNS traffic for testing |

**Key capabilities:**
- 🔴 **Live packet capture** via scapy with configurable analysis intervals
- 📁 **Offline PCAP analysis** with zero external capture dependencies
- 🤖 **Hybrid ML scoring** — 50% rule-based + 50% Isolation Forest anomaly score
- 📊 **Real-time dashboard** with per-IP risk timeline, alert feed, and tunnel registry
- 🧪 **Built-in traffic generator** with 5 configurable attack scenarios
- 💾 **CSV export** of all scored queries for post-session analysis

---

## Why DNS Tunneling is Dangerous

| Statistic | Detail |
|-----------|--------|
| **91%** of malware | Uses DNS for C2 communication |
| **53%** of organisations | Cannot detect DNS data exfiltration |
| **0%** of enterprise firewalls | Block DNS traffic by default |

DNS tunneling tools like **iodine**, **DNScat2**, and **dnstt** encode arbitrary data inside DNS subdomains and TXT/NULL/MX records. Because DNS packets are syntactically valid, signature-based IDS systems miss them entirely. DNSGuard detects them through statistical and behavioural analysis.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DNSGuard Pipeline                     │
│                                                                 │
│  ┌─────────┐    ┌─────────┐    ┌──────────┐    ┌──────────┐   │
│  │ CAPTURE │───▶│  PARSE  │───▶│ FEATURES │───▶│  DETECT  │   │
│  │         │    │         │    │          │    │          │   │
│  │ scapy   │    │ DNS wire│    │ 10 lexical│   │ Rules +  │   │
│  │ live OR │    │ format  │    │ + behav. │    │ Isolation│   │
│  │ PCAP    │    │ decoder │    │ features │    │ Forest   │   │
│  └─────────┘    └─────────┘    └──────────┘    └────┬─────┘   │
│                                                      │         │
│              ┌───────────────────────────────────────┘         │
│              ▼                                                  │
│  ┌───────────────────────────────────────────┐                 │
│  │              OUTPUTS                      │                 │
│  │  Console Report │ CSV File │ Dashboard    │                 │
│  └───────────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

The dashboard (`dashboard.py`) runs as a separate Flask server. The detector pushes scored events to it via `POST /live/push` during live capture, or results can be uploaded directly via the `/analyse` endpoint.

---

## Project Structure

```
DNSGuard/
│
├── README.md                  ← You are here
├── requirements.txt           ← Python dependencies
├── .gitignore
│
├── pcap_detector.py           ← Core detection engine
├── dashboard.py               ← Flask web dashboard (port 8080)
├── generate.py                ← DNS traffic simulator
│
├── samples/
│   └── demo.pcap              ← Sample capture file for testing
│
├── docs/
│   ├── DNSGuard_Presentation.pptx
│   └── architecture.png
│
└── results/
    └── sample_results.csv     ← Example scored output
```

---

## Installation

### Prerequisites

- Python 3.10 or higher
- `pip` package manager
- Root / Administrator privileges (required for live packet capture only)

### Step 1 — Clone the repository

```bash
git clone https://github.com/yourusername/DNSGuard.git
cd DNSGuard
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```
scapy>=2.5.0
pandas>=2.0.0
scikit-learn>=1.3.0
flask>=3.0.0
```

### Step 3 — Verify installation

```bash
python pcap_detector.py --help
```

---

## Usage

### 1. Live Capture Mode (`pcap_detector.py`)

Live mode requires root/administrator privileges because it sniffs raw network packets.

```bash
# Basic live capture on default interface, analyse every 30 seconds
sudo python pcap_detector.py --live

# Specify interface and interval
sudo python pcap_detector.py --live --iface eth0 --interval 30

# Run for exactly 5 minutes and save results
sudo python pcap_detector.py --live --iface eth0 --duration 300 --output results.csv

# Full example with all flags
sudo python pcap_detector.py --live --iface eth0 --interval 60 --duration 600 --output session.csv
```

**Live mode flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--live` | — | Enable real-time packet capture |
| `--iface` | System default | Network interface to sniff (e.g. `eth0`, `en0`, `Wi-Fi`) |
| `--interval` | `30` | Seconds between each analysis pass and alert output |
| `--duration` | `0` (∞) | Total capture duration in seconds. `0` = run until Ctrl-C |
| `--output` | None | Path to save rolling CSV results |

**Find your interface name:**
```bash
# Linux
ip a

# macOS
ifconfig

# Windows
ipconfig
```

---

### 2. Offline PCAP Analysis

No root required. Pass any `.pcap` file captured by Wireshark, tcpdump, or the `generate.py` tool.

```bash
# Analyse a specific PCAP file
python pcap_detector.py capture.pcap

# Use the included sample
python pcap_detector.py samples/demo.pcap
```

Results are printed to console and saved as `<filename>_results.csv` next to the input file.

**Capture a PCAP first with tcpdump:**
```bash
# Capture DNS traffic for 60 seconds
sudo tcpdump -i eth0 -w capture.pcap port 53
```

---

### 3. Web Dashboard (`dashboard.py`)

The dashboard is a standalone Flask application that provides a browser-based interface for both offline and live analysis.

```bash
python dashboard.py
```

Then open **http://127.0.0.1:8080** in your browser.

**Dashboard tabs:**

| Tab | Description |
|-----|-------------|
| **Overview** | Summary stats — total queries, tunnel count, risk distribution |
| **Alerts** | Searchable, filterable table of all scored DNS queries |
| **Live Feed** | Real-time animated stream of incoming events (live mode only) |
| **Confirmed Tunnels** | TunnelIPTracker registry — per-IP tunnel summary for non-technical users |
| **Settings** | Configure thresholds and display preferences |

**Uploading a PCAP via the dashboard:**
1. Open http://127.0.0.1:8080
2. Click **Upload PCAP** and select your `.pcap` file
3. The dashboard automatically runs the detector pipeline and renders results

**Connecting live capture to the dashboard:**

Run the detector and dashboard simultaneously in two terminals:

```bash
# Terminal 1 — start the dashboard
python dashboard.py

# Terminal 2 — start live capture (it auto-pushes to the dashboard)
sudo python pcap_detector.py --live --iface eth0 --interval 30
```

The detector pushes scored events to `POST /live/push` automatically during live mode, and the dashboard updates in real time.

---

### 4. Traffic Simulator (`generate.py`)

Generates realistic DNS traffic (normal + tunnel-like) for testing without real malware. Requires root because it crafts and sends raw packets via scapy.

```bash
# Default: mixed traffic (650 packets, loopback interface)
sudo python generate.py

# Specific mode
sudo python generate.py --mode tunnel --packets 200

# Gradual escalation demo (best for showcasing detection)
sudo python generate.py --mode escalate

# Burst attack from a single IP
sudo python generate.py --mode burst --packets 100 --delay 0.1

# On a specific interface
sudo python generate.py --mode mixed --iface eth0 --packets 300
```

**Traffic modes:**

| Mode | Description | Best for |
|------|-------------|----------|
| `mixed` | 40% tunnel, 60% normal (default) | Realistic demo |
| `normal` | Benign DNS queries only | Establishing a clean baseline |
| `tunnel` | High-entropy TXT/NULL/MX queries only | Testing detection sensitivity |
| `burst` | Rapid exfiltration from one attacker IP | Testing rate-based rules |
| `escalate` | 3-phase: normal (100) → mixed (80) → burst (120) | Faculty demo — shows full detection lifecycle |

**Recommended demo sequence:**
```bash
# Terminal 1
python dashboard.py

# Terminal 2
sudo python pcap_detector.py --live --iface lo --interval 20

# Terminal 3
sudo python generate.py --mode escalate
```

---

## Dashboard API Reference

The dashboard exposes a REST API used internally by the detector and available for custom integrations.

### `GET /`
Returns the full dashboard HTML.

---

### `GET /results?since=<version>`
Returns the current offline analysis state.

**Query params:**
- `since` (int, optional) — only return data if version is newer than this value (for polling)

**Response:**
```json
{
  "version": 3,
  "data": [ ...scored rows... ],
  "pcap_name": "capture.pcap",
  "thresholds": { "subdomain_length": 45, ... },
  "summary": { "total_queries": 320, "tunnels": 42, ... }
}
```

---

### `POST /analyse`
Upload a PCAP file for immediate analysis.

**Request:** `multipart/form-data` with field `pcap` containing the file.

```bash
curl -X POST http://127.0.0.1:8080/analyse \
  -F "pcap=@capture.pcap"
```

**Response:**
```json
{
  "ok": true,
  "version": 4,
  "pcap_name": "capture.pcap",
  "data": [ ...scored rows... ],
  "summary": {
    "total_queries": 320,
    "tunnels": 42,
    "high_risk": 38,
    "unique_sources": 5,
    "detector_path": "/path/to/pcap_detector.py"
  }
}
```

---

### `POST /live/push`
Stream scored events from the live detector to the dashboard.

**Request body (single event):**
```json
{
  "event": {
    "src_ip": "192.168.1.5",
    "query": "aGVsbG8gd29ybGQ.evil.com",
    "risk_score": 87.3,
    "risk_level": "High",
    "prediction": "TUNNEL",
    "record_type": "TXT"
  },
  "tracker": {
    "192.168.1.5": {
      "flagged_queries": 12,
      "max_risk_score": 87.3,
      "first_seen": "2025-01-01T10:00:00",
      "last_seen": "2025-01-01T10:05:00"
    }
  },
  "interface": "eth0",
  "window_seconds": 30
}
```

**Request body (batch):**
```json
{
  "events": [ ...array of scored rows... ],
  "tracker": { ... }
}
```

---

### `GET /live/status?since=<version>`
Returns current live-mode state including the TunnelIPTracker registry.

---

### `POST /live/reset`
Clears all live-mode state to start a fresh capture session.

```bash
curl -X POST http://127.0.0.1:8080/live/reset
```

---

## Detection Methodology

### Features Extracted Per DNS Query

| Feature | Type | Description |
|---------|------|-------------|
| `query_length` | Lexical | Total length of the FQDN |
| `subdomain_length` | Lexical | Length of the first-level subdomain label |
| `subdomain_entropy` | Lexical | Shannon entropy of the subdomain |
| `hex_ratio` | Lexical | Fraction of hex characters `[0-9a-f]` in subdomain |
| `digit_ratio` | Lexical | Fraction of digit characters in the full query |
| `dot_count` | Lexical | Number of labels (dots) in the FQDN |
| `query_rate_per_min` | Behavioral | Queries per minute from this source IP |
| `avg_entropy` | Behavioral | Mean subdomain entropy across all queries from this IP |
| `avg_response` | Behavioral | Average DNS response size in bytes from this IP |
| `special_type_count` | Behavioral | Count of TXT, NULL, MX queries from this IP |

### Hybrid Scoring Formula

```
risk_score = (rule_hits / 4) × 50  +  ml_score × 50
```

- **Rule-based component (50%):** Each of 4 threshold rules contributes 12.5 points when triggered
- **ML component (50%):** Isolation Forest anomaly score, normalised to 0–1
- **Classification:** `risk_score ≥ 50` → labeled **TUNNEL**, otherwise **normal**

### Rule Thresholds

| Rule | Threshold | Rationale |
|------|-----------|-----------|
| Subdomain length | > 45 characters | Legitimate subdomains rarely exceed 20 chars |
| Subdomain entropy | > 3.8 bits | Base64/hex encoded data has entropy ~5.0–6.0 |
| Query rate per minute | > 5 queries/min | Tunneling tools send continuously |
| Special type count | > 10 TXT/NULL/MX | Abuse of record types used to carry payloads |

### Risk Levels

| Level | Score Range | Action |
|-------|-------------|--------|
| 🟢 Low | 0 – 30 | No action required |
| 🟡 Medium | 31 – 60 | Worth investigating |
| 🔴 High | 61 – 100 | Act immediately — block and investigate |

---

## Sample Output

**Console report (excerpt):**
```
========================================================================
DNS TUNNELING DETECTION REPORT
Generated: 2025-04-20 14:32:01
========================================================================

Traffic Summary
------------------------------------------------------------------------
Total DNS queries analyzed : 300
Unique source IPs          : 5
Flagged as TUNNEL          : 84 (28.0%)
High risk queries          : 76
Medium risk queries        : 18
Low risk queries           : 206

Per-IP Summary
------------------------------------------------------------------------
IP                Queries  Max Risk  Avg Risk  Tunnels
----------------- ------- --------- --------- --------
10.0.7.142            120      94.2      81.3       84  suspicious host
192.168.1.15           80       8.1       5.2        0
...

Top High-Risk Alerts
------------------------------------------------------------------------
[ 94.2] 10.0.7.142       TXT
Query      : aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.seq42.c2.malware.net
Subdomain  : 52 chars   Entropy: 5.21   Hex ratio: 0.71   Response: 312 bytes
Reason     : Subdomain is unusually long (52 characters).
Reason     : Subdomain entropy is high (5.21).
Reason     : Source query rate is elevated (18.4 per minute).
```

**CSV output columns:**
```
ts, src_ip, dst_ip, sport, query, record_type, response_size,
subdomain_length, subdomain_entropy, hex_ratio, query_rate_per_min,
risk_score, risk_level, prediction
```

---

## Testing the Full Pipeline

The recommended way to verify everything works end-to-end:

```bash
# Step 1 — Start the dashboard
python dashboard.py &

# Step 2 — Start the live detector on loopback
sudo python pcap_detector.py --live --iface lo --interval 20 --output test_results.csv &

# Step 3 — Run the escalation demo
sudo python generate.py --mode escalate --iface lo

# Step 4 — Open the dashboard
open http://127.0.0.1:8080
```

You should see the risk score escalate through Low → Medium → High across the three phases as the `escalate` mode progresses.

---

## Limitations

| Limitation | Details |
|------------|---------|
| **Evasion via padding** | Attackers can pad subdomains with dictionary words to reduce entropy below the 3.8-bit threshold |
| **Encrypted DNS (DoH/DoT)** | DNS-over-HTTPS hides query content entirely — the parser cannot inspect it |
| **ML cold start** | Isolation Forest requires ≥2 queries to produce a score; single queries are scored by rules only |
| **IPv4 only** | The raw PCAP parser currently skips IPv6 packets (EtherType `0x86DD`) |
| **UDP only** | DNS over TCP (used for large responses) is not yet parsed |

---

## References

1. Paxson et al. — *Detecting DNS Tunneling using Entropy and Statistical Methods.* IEEE/IFIP DSN, 2018.
2. Silva & Santos — *Flow-Based Anomaly Detection for DNS Covert Channels.* ACM CCS Workshop, 2019.
3. Nguyen et al. — *Machine Learning Techniques for DNS Tunneling Detection.* IEEE TNSM, 2020.
4. Smith & Lee — *Hybrid SIEM-DPI Approaches to DNS Data Exfiltration.* USENIX Security Symposium, 2021.
5. Liu F.T. et al. — *Isolation Forest: anomaly detection without a distance measure.* IEEE ICDM, 2008.
6. iodine / DNScat2 — Open-source DNS tunneling tool documentation. GitHub, 2006–2024.
7. Zeek/Bro — DNS Analysis Scripts and network monitoring framework. zeek.org, 2024.

---

<div align="center">

**DNSGuard** — Real-Time DNS Threat Intelligence

B.Tech CSE Final Year Project · Supervised by Dr. Richa Kumari

</div>
