# DNSGuard 🛡️
### DNS Tunneling Detection & Real-Time Threat Intelligence System

> **Final Year Project — B.Tech Computer Science & Engineering**
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
| `pcap_detector.py` | Core detection engine — live capture or offline PCAP analysis (1,436 lines) |
| `dashboard.py` | Flask web dashboard — real-time visualisation at `http://localhost:8080` (2,436 lines) |
| `generate.py` | Traffic simulator — generates realistic normal + tunnel DNS traffic for testing |

**Key capabilities:**
- 🔴 **Live packet capture** via scapy with configurable sliding window
- 📁 **Offline PCAP analysis** with zero external capture dependencies
- 📐 **Hybrid scoring** — 50% rule-based thresholds + 50% Isolation Forest anomaly score
- 🔔 **Desktop alerts** — native popup notification on every new TUNNEL detection (10s cooldown per IP)
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

> These figures are industry-reported statistics from threat intelligence surveys, not measurements taken by DNSGuard itself. The 0% figure means zero enterprise firewalls block port 53 outbound by default.

DNS tunneling tools like **iodine**, **DNScat2**, and **dnstt** encode arbitrary data inside DNS subdomains and TXT/NULL/MX records. Because DNS packets are syntactically valid, signature-based IDS systems miss them entirely. DNSGuard detects them through statistical and behavioural analysis.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DNSGuard Pipeline                        │
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

The dashboard (`dashboard.py`) runs as a separate Flask server. The detector pushes scored events to it via `POST /live/push` during live capture, or results can be uploaded directly via the `/analyse` endpoint. Both processes must run simultaneously in separate terminals for live mode.

---

## Project Structure

```
DNSGuard/
│
├── README.md                  ← You are here
├── requirements.txt           ← Python dependencies
├── .gitignore
│
├── pcap_detector.py           ← Core detection engine (1,436 lines)
├── dashboard.py               ← Flask web dashboard (port 8080, 2,436 lines)
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
git clone https://github.com/vinayak-sriv/DNSGuard.git
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
numpy>=1.24.0
flask>=3.0.0
requests>=2.31.0
plyer>=2.1.0
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
# Basic live capture on default interface (eth0)
sudo python pcap_detector.py --live

# Specify interface
sudo python pcap_detector.py --live --iface eth0

# Custom sliding window (seconds of traffic to score at once)
sudo python pcap_detector.py --live --iface eth0 --window 120

# With dashboard streaming
sudo python pcap_detector.py --live --iface eth0 --dashboard http://127.0.0.1:8080

# Suppress desktop popup notifications
sudo python pcap_detector.py --live --iface eth0 --no-notify

# Disable dashboard push
sudo python pcap_detector.py --live --iface eth0 --no-dashboard
```

**Live mode flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--live` | — | Enable real-time packet capture |
| `--iface` | `eth0` | Network interface to sniff (e.g. `eth0`, `en0`, `Wi-Fi`) |
| `--window` | `300` | Sliding window size in seconds — how much recent traffic is scored per packet |
| `--dashboard` | `http://127.0.0.1:8080` | DNS Shield dashboard URL for event streaming |
| `--no-notify` | — | Suppress desktop popup notifications |
| `--no-dashboard` | — | Disable streaming to the DNS Shield dashboard |

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

# With dashboard push after analysis
python pcap_detector.py capture.pcap --dashboard http://127.0.0.1:8080

# Suppress notifications
python pcap_detector.py capture.pcap --no-notify
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
| **Confirmed Tunnels** | TunnelIPTracker registry — per-IP tunnel summary |
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
sudo python pcap_detector.py --live --iface eth0
```

The detector pushes scored events to `POST /live/push` automatically during live mode, and the dashboard updates in real time without page refresh.

---

### 4. Traffic Simulator (`generate.py`)

Generates realistic DNS traffic (normal + tunnel-like) for testing without real malware. Requires root because it crafts and sends raw packets via scapy.

```bash
# Default: mixed traffic (300 packets)
sudo python generate.py

# Specific mode
sudo python generate.py --mode tunnel --packets 200

# Gradual escalation demo (best for showcasing detection)
sudo python generate.py --mode escalate

# Burst attack from a single IP
sudo python generate.py --mode burst --packets 100 --delay 0.1

# Normal benign baseline only
sudo python generate.py --mode normal --packets 100
```

**Traffic modes:**

| Mode | Description | Best for |
|------|-------------|----------|
| `mixed` | 40% tunnel, 60% normal (default) | Realistic demo |
| `normal` | Benign DNS queries only | Establishing a clean baseline |
| `tunnel` | High-entropy hex TXT/NULL/MX queries only | Testing detection sensitivity |
| `burst` | Rapid exfiltration from one fixed attacker IP | Testing rate-based rules |
| `escalate` | 3-phase: normal (100) → mixed (80) → burst (120) | Faculty demo — shows full detection lifecycle |

> **Note:** Tunnel queries use hex-encoded payloads (24+ hex chars per label) to reliably breach all three lexical thresholds: `subdomain_length > 45`, `subdomain_entropy > 3.8`, and `hex_ratio > 0.60`. Two fixed attacker IPs (`10.0.7.100`, `10.0.7.200`) are used so each builds sufficient query rate independently during the mixed phase.

**Recommended demo sequence:**
```bash
# Terminal 1
python dashboard.py

# Terminal 2
sudo python pcap_detector.py --live --iface lo

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
    "src_ip": "10.0.7.100",
    "query": "aabbccddeeff00112233.seq42.tunnel.evil.io",
    "risk_score": 87.3,
    "risk_level": "High",
    "prediction": "TUNNEL",
    "record_type": "TXT"
  },
  "tracker": {
    "10.0.7.100": {
      "flagged_queries": 12,
      "max_risk_score": 87.3,
      "first_seen": "2025-01-01T10:00:00",
      "last_seen": "2025-01-01T10:05:00"
    }
  },
  "interface": "eth0",
  "window_seconds": 300
}
```

**Request body (batch — offline mode):**
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
| `subdomain_length` | Lexical | Length of payload subdomain (all labels before registered domain, concatenated) |
| `subdomain_entropy` | Lexical | Shannon entropy of the payload subdomain |
| `hex_ratio` | Lexical | Fraction of hex characters `[0-9a-f]` in subdomain |
| `digit_ratio` | Lexical | Fraction of digit characters in the full query |
| `dot_count` | Lexical | Number of labels (dots) in the FQDN |
| `query_rate_per_min` | Behavioral | Queries per minute from this source IP |
| `avg_entropy` | Behavioral | Mean subdomain entropy across all queries from this IP |
| `avg_response` | Behavioral | Average DNS response size in bytes from this IP |
| `special_type_count` | Behavioral | Count of TXT, NULL, MX queries from this IP |

> **Lexical features** are computed per individual DNS query. **Behavioral features** are aggregated per source IP across the sliding window — they reflect patterns over time, not a single query.

### Hybrid Scoring Formula

```
risk_score = (rule_hits / TOTAL_RULES) × 50  +  ml_score × 50
```

- **Rule-based component (50%):** Each rule threshold breach contributes equally. `TOTAL_RULES = len(THRESHOLDS)` — currently 4, auto-adjusts if rules are added or removed.
- **Isolation Forest component (50%):** Anomaly score normalised to 0–1. Model is trained fresh on each session's traffic with `contamination=0.25`.
- **Classification:** `risk_score ≥ 50` → labeled **TUNNEL**, otherwise **normal**. A TUNNEL label triggers a desktop notification (max once per IP per 10 seconds).

### Rule Thresholds

| Rule | Threshold | Rationale |
|------|-----------|-----------|
| Subdomain length | > 45 characters | Legitimate subdomains rarely exceed 20 chars |
| Subdomain entropy | > 3.8 bits | Hex/base64 encoded data has entropy ~5.0–6.0 |
| Query rate per minute | > 5 queries/min | Tunneling tools send continuously |
| Special type count | > 10 TXT/NULL/MX | Abuse of record types used to carry payloads |

### Risk Levels

| Level | Score Range | Action |
|-------|-------------|--------|
| 🟢 Low | 0 – 30 | No action required |
| 🟡 Medium | 30 – 60 | Worth investigating — query may still be labelled TUNNEL |
| 🔴 High | 60 – 100 | Act immediately — block and investigate |

> A query with score ≥ 50 is labelled **TUNNEL** regardless of risk level. Medium-risk queries (30–60) can therefore also carry a TUNNEL label and trigger notifications.

---

## Sample Output

**Console report (excerpt):**
```
========================================================================
DNS TUNNELING DETECTION REPORT
Generated: 2025-04-24 14:32:01
========================================================================

Traffic Summary
------------------------------------------------------------------------
Total DNS queries analysed : 300
Unique source IPs          : 3
Flagged as TUNNEL          : 127 (42.3%)
High risk queries          : 41
Medium risk queries        : 111
Low risk queries           : 148

Per-IP Summary
------------------------------------------------------------------------
IP                Queries  Max Risk  Avg Risk  Tunnels
----------------- ------- --------- --------- --------
10.0.7.189            120     83.8      74.1      113  *** SUSPECTED TUNNEL SOURCE ***
10.0.7.100             80      8.1       5.2        0
...

Top High-Risk Alerts
------------------------------------------------------------------------
[ 83.8] 10.0.7.189       TXT
Query      : 2f4a8bc3d1e09f5a7b6c.4e8d2a1f3b5c.s4955.tunnel.evil.io
Subdomain  : 48 chars   Entropy: 4.06   Hex ratio: 0.97   Response: 80 bytes
Reason     : Subdomain is unusually long (48 characters).
Reason     : Subdomain entropy is high (4.06).
Reason     : Source query rate is elevated (179.7/min).
Reason     : Source sent many TXT/NULL/MX queries (57).
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
python dashboard.py

# Step 2 — In a new terminal, start the live detector on loopback
sudo python pcap_detector.py --live --iface lo --dashboard http://127.0.0.1:8080

# Step 3 — In a third terminal, run the escalation demo
sudo python generate.py --mode escalate

# Step 4 — Open the dashboard
xdg-open http://127.0.0.1:8080   # Linux
open http://127.0.0.1:8080        # macOS
```

You should see the risk score escalate through Low → Medium → High across the three phases as the `escalate` mode progresses. Desktop popups will fire when TUNNEL predictions are made.

---

## Limitations

| Limitation | Details |
|------------|---------|
| **Evasion via padding** | Attackers can pad subdomains with dictionary words to reduce entropy below the 3.8-bit threshold. The Isolation Forest component partially compensates. |
| **Encrypted DNS (DoH/DoT)** | DNS-over-HTTPS hides query content entirely — the wire-format parser cannot inspect it |
| **Isolation Forest cold start** | Requires ≥2 queries in the window to produce a score; single queries are scored by rules only |
| **IPv4 only** | The raw PCAP parser skips IPv6 packets (EtherType `0x86DD`) |
| **UDP only** | DNS over TCP (used for large responses) is not yet parsed |

---

## References

1. Farnham, G. & Atlasis, A. — *Detecting DNS Tunneling.* SANS Institute InfoSec Reading Room, 2013.
   https://www.sans.org/white-papers/34152/

2. Ellens, W. et al. — *Flow-based Detection of DNS Tunnels.* Lecture Notes in Computer Science, Vol. 7943, pp. 124–135, Springer, 2013.
   https://link.springer.com/chapter/10.1007/978-3-642-40973-7_11

3. Homem, I., Papapetrou, P. & Dosis, S. — *Information-Entropy-Based DNS Tunnel Prediction.* IFIP Advances in Information and Communication Technology, Vol. 532, Springer, 2018.
   https://link.springer.com/chapter/10.1007/978-3-319-99277-8_8

4. Jaworski, S. — *Using Splunk to Detect DNS Tunneling.* SANS Institute InfoSec Reading Room, 2016.
   https://www.sans.org/white-papers/37022/

5. Liu, F.T., Ting, K.M. & Zhou, Z.-H. — *Isolation Forest.* 2008 Eighth IEEE International Conference on Data Mining (ICDM), pp. 413–422.
   https://ieeexplore.ieee.org/document/4781136/

6. iodine (Ekman & Andersson) — Open-source IP-over-DNS tunnel. GitHub, 2006–2024.
   https://github.com/yarrick/iodine
   DNScat2 (Coppins) — DNS-based command and control framework. GitHub, 2013–2024.
   https://github.com/iagox86/dnscat2

7. Zeek Network Security Monitor — DNS analysis framework. zeek.org, 2024.
   https://zeek.org

---

<div align="center">

**DNSGuard** — DNS Tunneling Detection & Real-Time Threat Intelligence System

B.Tech CSE Final Year Project · Supervised by Dr. Richa Kumari · UPES Dehradun, 2025

</div>
