"""
DNS Tunneling Detector
======================
Supports two modes:
  - Offline : analyse an existing .pcap file (original behaviour)
  - Live    : sniff packets in real time on a network interface (new)

New features over the original:
  1. TunnelIPTracker  – maintains a persistent registry of confirmed tunnel
                        source IPs with timestamps, query counts, and reasons.
  2. Real-time scoring – each captured packet is scored immediately using a
                        per-IP sliding-window of recent queries so that
                        behavioural features stay current.
  3. System popup     – a native desktop notification is raised whenever a
                        High-risk query is detected (plyer → notify-send →
                        osascript → ctypes fallback chain).
  4. Dashboard push   – every scored event (and the TunnelIPTracker snapshot)
                        is streamed to the DNS Shield dashboard in real time
                        via POST /live/push.  The dashboard URL is configured
                        with --dashboard (default: http://127.0.0.1:8080).
                        Use --no-dashboard to disable.

Usage
-----
  # Offline (unchanged interface):
  python pcap_detector.py capture.pcap

  # Live capture (requires scapy + root / cap_net_raw):
  python pcap_detector.py --live --iface eth0

  # Live with custom sliding window (seconds):
  python pcap_detector.py --live --iface eth0 --window 120

  # Live with dashboard streaming:
  python pcap_detector.py --live --iface eth0 --dashboard http://127.0.0.1:8080

  # Offline analysis with dashboard push (pushes full result set once):
  python pcap_detector.py capture.pcap --dashboard http://127.0.0.1:8080

  # Suppress desktop popups:
  python pcap_detector.py capture.pcap --no-notify

  # Suppress dashboard push:
  python pcap_detector.py --live --iface eth0 --no-dashboard

Dependencies
------------
  pip install pandas scikit-learn          # core (unchanged)
  pip install scapy                        # live capture only
  pip install plyer                        # desktop notifications (optional)
  pip install requests                     # dashboard streaming (optional)
"""

from __future__ import annotations

import argparse
import collections
import datetime
import math
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Optional runtime dependencies
# ---------------------------------------------------------------------------

try:
    from plyer import notification as _plyer_notification   # type: ignore
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

try:
    from scapy.all import DNS, DNSQR, IP, UDP, sniff as _scapy_sniff  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import requests as _requests   # type: ignore
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QTYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}

THRESHOLDS: dict[str, float] = {
    "subdomain_length": 45,
    "subdomain_entropy": 3.8,
    "query_rate_per_min": 5.0,
    "special_type_count": 10,
}

ML_FEATURES: list[str] = [
    "query_length",
    "subdomain_length",
    "subdomain_entropy",
    "dot_count",
    "digit_ratio",
    "hex_ratio",
    "query_count",
    "avg_entropy",
    "query_rate_per_min",
    "avg_response",
]

REPORT_COLUMNS: list[str] = [
    "ts",
    "src_ip",
    "dst_ip",
    "sport",
    "query",
    "record_type",
    "response_size",
    "subdomain",
    "query_length",
    "subdomain_length",
    "subdomain_entropy",
    "dot_count",
    "digit_ratio",
    "hex_ratio",
    "is_special_type",
    "query_count",
    "unique_domains",
    "avg_qlen",
    "avg_entropy",
    "avg_response",
    "special_type_count",
    "query_rate_per_min",
    "rule_hits",
    "rule_reasons",
    "ml_score",
    "risk_score",
    "risk_level",
    "prediction",
]

OUTPUT_COLUMNS: list[str] = [
    "ts",
    "src_ip",
    "dst_ip",
    "sport",
    "query",
    "record_type",
    "response_size",
    "subdomain_length",
    "subdomain_entropy",
    "hex_ratio",
    "query_rate_per_min",
    "risk_score",
    "risk_level",
    "prediction",
]

SEPARATOR = "-" * 72
NOTIFICATION_COOLDOWN_SECONDS = 30   # minimum gap between popups per IP
LIVE_WINDOW_SECONDS_DEFAULT  = 300   # 5-minute sliding window for live mode

DASHBOARD_URL_DEFAULT        = "http://127.0.0.1:8080"
DASHBOARD_PUSH_TIMEOUT       = 1     # seconds — never block packet capture
DASHBOARD_MAX_QUEUE          = 500   # drop oldest if queue grows beyond this


# ===========================================================================
# Section 1 – Tunnel IP Tracker
# ===========================================================================

class TunnelIPTracker:
    """Thread-safe registry of IPs confirmed as DNS tunnel sources.

    Each time an IP produces a High-risk or TUNNEL-predicted query it is
    'flagged' here. The tracker records:
      - first_seen / last_seen timestamps
      - total number of flagged queries
      - peak risk score observed
      - up to five representative query samples
      - the union of all rule reasons that were triggered
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tunnels: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def flag(
        self,
        ip: str,
        query: str,
        risk_score: float,
        reasons: list[str],
    ) -> bool:
        """Register a high-risk event from *ip*. Returns True if first time."""
        now = datetime.datetime.now()
        with self._lock:
            is_new = ip not in self._tunnels
            if is_new:
                self._tunnels[ip] = {
                    "first_seen": now,
                    "last_seen": now,
                    "flagged_queries": 0,
                    "max_risk_score": 0.0,
                    "sample_queries": [],
                    "reasons": set(),
                }
            entry = self._tunnels[ip]
            entry["last_seen"] = now
            entry["flagged_queries"] += 1
            entry["max_risk_score"] = max(entry["max_risk_score"], risk_score)
            if len(entry["sample_queries"]) < 5:
                entry["sample_queries"].append(query)
            entry["reasons"].update(reasons)
            return is_new

    def get_all(self) -> dict[str, dict]:
        """Return a snapshot of all tracked tunnel IPs."""
        with self._lock:
            return {ip: dict(info) for ip, info in self._tunnels.items()}

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._tunnels)

    def print_summary(self) -> None:
        """Print a formatted table of all identified tunnel IPs."""
        tunnels = self.get_all()
        print("\n" + "=" * 72)
        print("IDENTIFIED TUNNEL IPs")
        print("=" * 72)
        if not tunnels:
            print("  No tunnel source IPs were identified in this session.")
            print("=" * 72)
            return
        sorted_ips = sorted(
            tunnels.items(),
            key=lambda kv: kv[1]["max_risk_score"],
            reverse=True,
        )
        for ip, info in sorted_ips:
            first = info["first_seen"].strftime("%Y-%m-%d %H:%M:%S")
            last  = info["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n  [TUNNEL] {ip}")
            print(f"    First flagged  : {first}")
            print(f"    Last flagged   : {last}")
            print(f"    Flagged queries: {info['flagged_queries']}")
            print(f"    Peak risk score: {info['max_risk_score']:.1f}")
            samples = info["sample_queries"][:3]
            print(f"    Sample queries : {' | '.join(s[:60] for s in samples)}")
            for reason in list(info["reasons"])[:4]:
                print(f"    Evidence       : {reason}")
        print("=" * 72)




# ===========================================================================
# Section 1b – Dashboard Pusher
# ===========================================================================

class DashboardPusher:
    """Non-blocking background worker that streams scored events to the
    DNS Shield dashboard (dashboard.py) via POST /live/push.

    Design goals
    ------------
    - Packet capture is NEVER blocked or delayed by dashboard I/O.
    - A daemon thread drains a queue of pending payloads.
    - If the dashboard is unreachable the pusher silently drops events and
      logs a single warning (no repeated noise).
    - Supports both live-mode (one event per packet) and offline-mode
      (batch push of the full result set at the end).
    """

    def __init__(
        self,
        base_url: str = DASHBOARD_URL_DEFAULT,
        enabled: bool = True,
        interface: str = "",
        window_seconds: int = LIVE_WINDOW_SECONDS_DEFAULT,
    ) -> None:
        self.base_url        = base_url.rstrip("/")
        self.enabled         = enabled and REQUESTS_AVAILABLE
        self.interface       = interface
        self.window_seconds  = window_seconds
        self._queue: "collections.deque[dict]" = collections.deque(maxlen=DASHBOARD_MAX_QUEUE)
        self._warned         = False   # print connectivity warning once only
        self._lock           = threading.Lock()

        if enabled and not REQUESTS_AVAILABLE:
            print(
                "  [dashboard] 'requests' not installed — dashboard push disabled.\n"
                "              Install with: pip install requests"
            )

        if self.enabled:
            self._worker = threading.Thread(
                target=self._drain_loop, daemon=True, name="dashboard-pusher"
            )
            self._worker.start()
            print(f"  [dashboard] Streaming to {self.base_url}/live/push")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def push_event(
        self,
        scored_row: "pd.Series",
        tracker: TunnelIPTracker,
    ) -> None:
        """Enqueue a single scored row for async delivery. Never blocks."""
        if not self.enabled:
            return
        payload = self._build_event_payload(scored_row, tracker)
        self._queue.append(payload)

    def push_batch(
        self,
        results: "pd.DataFrame",
        tracker: TunnelIPTracker,
        pcap_name: str = "",
    ) -> None:
        """Synchronously push an entire offline result set to the dashboard.

        Called once at the end of offline analysis. Uses /live/push with a
        batch payload so the Live Feed tab populates immediately.
        """
        if not self.enabled:
            return
        if results.empty:
            return

        events = []
        for _, row in results.iterrows():
            events.append(self._row_to_dict(row))

        tracker_snap = self._tracker_snapshot(tracker)
        payload = {
            "events":         events,
            "tracker":        tracker_snap,
            "interface":      f"offline:{pcap_name}" if pcap_name else "offline",
            "window_seconds": 0,
        }
        self._send(payload, label="batch")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_event_payload(
        self,
        row: "pd.Series",
        tracker: TunnelIPTracker,
    ) -> dict:
        return {
            "event":          self._row_to_dict(row),
            "tracker":        self._tracker_snapshot(tracker),
            "interface":      self.interface,
            "window_seconds": self.window_seconds,
        }

    @staticmethod
    def _row_to_dict(row: "pd.Series") -> dict:
        """Convert a scored pandas Series to a JSON-safe dict."""
        import math as _math
        out: dict = {}
        for k, v in row.items():
            if hasattr(v, "item"):
                try:
                    v = v.item()
                except Exception:
                    v = str(v)
            if isinstance(v, float) and (_math.isnan(v) or _math.isinf(v)):
                v = None
            elif isinstance(v, list):
                v = [str(i) for i in v]
            elif hasattr(v, "__iter__") and not isinstance(v, (str, bytes)):
                v = list(v)
            out[k] = v
        # Ensure rule_reasons is always a list of strings
        rr = out.get("rule_reasons")
        if isinstance(rr, str):
            out["rule_reasons"] = [s.strip() for s in rr.split(";") if s.strip()]
        elif not isinstance(rr, list):
            out["rule_reasons"] = []
        return out

    @staticmethod
    def _tracker_snapshot(tracker: TunnelIPTracker) -> dict:
        """Serialize tracker to a JSON-safe dict."""
        snap = {}
        for ip, info in tracker.get_all().items():
            snap[ip] = {
                "first_seen":     str(info.get("first_seen", "")),
                "last_seen":      str(info.get("last_seen", "")),
                "flagged_queries": int(info.get("flagged_queries", 0)),
                "max_risk_score":  float(info.get("max_risk_score", 0.0)),
                "sample_queries":  list(info.get("sample_queries", [])),
                "reasons":         list(info.get("reasons", [])),
            }
        return snap

    def _send(self, payload: dict, label: str = "event") -> bool:
        """HTTP POST to /live/push. Returns True on success."""
        url = f"{self.base_url}/live/push"
        try:
            resp = _requests.post(url, json=payload, timeout=DASHBOARD_PUSH_TIMEOUT)
            if resp.status_code == 200:
                self._warned = False   # reset warning flag on success
                return True
            else:
                if not self._warned:
                    print(f"  [dashboard] Push returned HTTP {resp.status_code}")
                    self._warned = True
        except Exception as exc:
            if not self._warned:
                print(
                    f"  [dashboard] Cannot reach {url} — "
                    f"dashboard push paused ({type(exc).__name__})."
                )
                self._warned = True
        return False

    def _drain_loop(self) -> None:
        """Background thread: drain the queue one payload at a time."""
        while True:
            try:
                if self._queue:
                    payload = self._queue.popleft()
                    self._send(payload)
                else:
                    time.sleep(0.05)
            except Exception:
                time.sleep(0.1)


# ===========================================================================
# Section 2 – System Popup Notifications
# ===========================================================================

def send_system_notification(title: str, message: str) -> None:
    """Dispatch a native desktop popup using the best available mechanism.

    Priority chain:
      1. plyer  (cross-platform Python library)
      2. notify-send  (Linux / freedesktop)
      3. osascript    (macOS)
      4. ctypes MessageBox  (Windows fallback)
    """
    # 1. plyer
    if PLYER_AVAILABLE:
        try:
            _plyer_notification.notify(
                title=title,
                message=message,
                app_name="DNS Tunnel Detector",
                timeout=10,
            )
            return
        except Exception:
            pass  # fall through to OS-level methods

    # 2. Linux – notify-send
    if sys.platform.startswith("linux"):
        try:
            subprocess.Popen(
                ["notify-send", "--urgency=critical", "--icon=dialog-warning",
                 title, message],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except FileNotFoundError:
            pass

    # 3. macOS – osascript
    if sys.platform == "darwin":
        safe_msg   = message.replace('"', '\\"')
        safe_title = title.replace('"', '\\"')
        script = (
            f'display notification "{safe_msg}" '
            f'with title "{safe_title}" '
            f'sound name "Basso"'
        )
        try:
            subprocess.Popen(
                ["osascript", "-e", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        except FileNotFoundError:
            pass

    # 4. Windows – ctypes MessageBox (modal, last resort)
    if sys.platform == "win32":
        try:
            import ctypes
            # MB_ICONWARNING | MB_SYSTEMMODAL | MB_OK
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x30 | 0x1000)
        except Exception:
            pass

    # If everything failed, silently continue – detection still works.


def _notify_async(title: str, message: str) -> None:
    """Fire a notification in a daemon thread so capture is never blocked."""
    threading.Thread(
        target=send_system_notification,
        args=(title, message),
        daemon=True,
    ).start()


# ===========================================================================
# Section 3 – Core detection pipeline (unchanged from original)
# ===========================================================================

def _empty_feature_frame() -> pd.DataFrame:
    """Return an empty frame with all columns used later in the pipeline."""
    return pd.DataFrame(columns=REPORT_COLUMNS)


def _parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS name from wire format while safely following pointers."""
    if depth > 10 or offset >= len(data):
        return "", offset

    labels: list[str] = []
    current_offset = offset

    while current_offset < len(data):
        length = data[current_offset]

        if length == 0:
            current_offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if current_offset + 1 >= len(data):
                return ".".join(labels), len(data)
            pointer = ((length & 0x3F) << 8) | data[current_offset + 1]
            suffix, _ = _parse_dns_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            current_offset += 2
            break

        current_offset += 1
        label_end = current_offset + length
        if label_end > len(data):
            return ".".join(labels), len(data)

        label = data[current_offset:label_end].decode("ascii", errors="replace")
        labels.append(label)
        current_offset = label_end

    return ".".join(labels), current_offset


def parse_pcap(path: str | Path) -> list[dict]:
    """Parse a PCAP file and extract DNS query records."""
    capture_path = Path(path)
    if not capture_path.exists():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    print(f"[1/4] Reading packet capture: {capture_path}")
    raw = capture_path.read_bytes()

    if len(raw) < 24:
        raise ValueError("The file is too small to be a valid PCAP capture.")

    magic_bytes = raw[:4]
    endian_map = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = endian_map.get(magic_bytes)
    if endian is None:
        raise ValueError(
            "Unsupported capture format. Expected a standard PCAP file."
        )

    offset = 24
    outstanding_queries: dict[tuple[str, int, str, int], dict] = {}
    records: list[dict] = []

    while offset + 16 <= len(raw):
        ts_sec, ts_usec, caplen, _origlen = struct.unpack_from(
            endian + "IIII", raw, offset
        )
        offset += 16

        if offset + caplen > len(raw):
            break

        packet = raw[offset : offset + caplen]
        offset += caplen

        if len(packet) < 14 + 20 + 8:
            continue

        eth_type = struct.unpack_from("!H", packet, 12)[0]
        if eth_type != 0x0800:
            continue

        ip_start = 14
        ip_header_length = (packet[ip_start] & 0x0F) * 4
        if ip_header_length < 20 or len(packet) < ip_start + ip_header_length + 8:
            continue

        protocol = packet[ip_start + 9]
        if protocol != 17:
            continue

        src_ip = ".".join(str(b) for b in packet[ip_start + 12 : ip_start + 16])
        dst_ip = ".".join(str(b) for b in packet[ip_start + 16 : ip_start + 20])

        udp_start = ip_start + ip_header_length
        sport, dport = struct.unpack_from("!HH", packet, udp_start)
        dns = packet[udp_start + 8 :]

        if len(dns) < 12:
            continue

        txid  = struct.unpack_from("!H", dns, 0)[0]
        flags = struct.unpack_from("!H", dns, 2)[0]
        qr    = (flags >> 15) & 1
        qdcount = struct.unpack_from("!H", dns, 4)[0]

        if qdcount < 1:
            continue

        qname, q_offset = _parse_dns_name(dns, 12)
        if not qname or q_offset + 4 > len(dns):
            continue

        qtype_raw = struct.unpack_from("!H", dns, q_offset)[0]
        qtype     = QTYPE_MAP.get(qtype_raw, str(qtype_raw))

        if qr == 0 and dport == 53:
            record = {
                "ts": ts_sec + ts_usec / 1e6,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "sport": sport,
                "query": qname.lower(),
                "record_type": qtype,
                "response_size": 80,
            }
            outstanding_queries[(src_ip, sport, dst_ip, txid)] = record
            records.append(record)
        elif qr == 1 and sport == 53:
            match_key = (dst_ip, dport, src_ip, txid)
            if match_key in outstanding_queries:
                outstanding_queries[match_key]["response_size"] = len(packet)

    print(f"      Parsed {len(records)} DNS queries")
    return records


def _entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0
    frequencies: dict[str, int] = {}
    for character in text:
        frequencies[character] = frequencies.get(character, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def extract_features(records: list[dict]) -> pd.DataFrame:
    """Build lexical and per-client behavioural features from parsed queries."""
    if not records:
        return _empty_feature_frame()

    df = pd.DataFrame(records)
    df["query"]       = df["query"].fillna("").astype(str)
    df["record_type"] = df["record_type"].fillna("UNKNOWN").astype(str)

    df["subdomain"]         = df["query"].apply(
        lambda q: q.split(".")[0] if "." in q else q
    )
    df["query_length"]      = df["query"].str.len()
    df["subdomain_length"]  = df["subdomain"].str.len()
    df["subdomain_entropy"] = df["subdomain"].apply(_entropy)
    df["dot_count"]         = df["query"].str.count(r"\.")
    df["digit_ratio"]       = df["query"].apply(
        lambda q: sum(c.isdigit() for c in q) / max(len(q), 1)
    )
    df["hex_ratio"] = df["subdomain"].apply(
        lambda label: sum(c in "0123456789abcdef" for c in label.lower())
        / max(len(label), 1)
    )
    df["is_special_type"] = df["record_type"].isin(["TXT", "NULL", "MX"]).astype(int)

    capture_span_seconds = max(df["ts"].max() - df["ts"].min(), 0)
    window_minutes = max(capture_span_seconds / 60, 1)

    client_features = (
        df.groupby("src_ip")
        .agg(
            query_count     =("query",           "count"),
            unique_domains  =("query",           "nunique"),
            avg_qlen        =("query_length",    "mean"),
            avg_entropy     =("subdomain_entropy","mean"),
            avg_response    =("response_size",   "mean"),
            special_type_count=("is_special_type","sum"),
        )
        .reset_index()
    )
    client_features["query_rate_per_min"] = (
        client_features["query_count"] / window_minutes
    )

    return df.merge(client_features, on="src_ip", how="left")


def rule_score(row: pd.Series) -> tuple[int, list[str]]:
    """Assign rule hits and human-readable reasons for a DNS query."""
    hits = 0
    reasons: list[str] = []

    if row["subdomain_length"] > THRESHOLDS["subdomain_length"]:
        hits += 1
        reasons.append(
            f"Subdomain is unusually long ({int(row['subdomain_length'])} characters)."
        )
    if row["subdomain_entropy"] > THRESHOLDS["subdomain_entropy"]:
        hits += 1
        reasons.append(
            f"Subdomain entropy is high ({row['subdomain_entropy']:.2f})."
        )
    if row["query_rate_per_min"] > THRESHOLDS["query_rate_per_min"]:
        hits += 1
        reasons.append(
            f"Source query rate is elevated ({row['query_rate_per_min']:.1f}/min)."
        )
    if row["special_type_count"] > THRESHOLDS["special_type_count"]:
        hits += 1
        reasons.append(
            f"Source sent many TXT/NULL/MX queries ({int(row['special_type_count'])})."
        )

    return hits, reasons


def detect(df: pd.DataFrame) -> pd.DataFrame:
    """Run rule-based and anomaly-based scoring on the feature frame."""
    if df.empty:
        return _empty_feature_frame()

    scored = df.copy()

    rule_results      = scored.apply(rule_score, axis=1)
    scored["rule_hits"]    = rule_results.apply(lambda r: r[0])
    scored["rule_reasons"] = rule_results.apply(lambda r: r[1])

    if len(scored) >= 2:
        feature_matrix  = scored[ML_FEATURES].fillna(0)
        scaled_features = StandardScaler().fit_transform(feature_matrix)
        model = IsolationForest(
            contamination=0.25,
            n_estimators=200,
            random_state=42,
        )
        model.fit(scaled_features)
        raw_scores  = model.decision_function(scaled_features)
        score_range = raw_scores.max() - raw_scores.min()
        scored["ml_score"] = 1 - (
            (raw_scores - raw_scores.min()) / (score_range + 1e-9)
        )
    else:
        scored["ml_score"] = 0.0

    scored["risk_score"] = (
        (scored["rule_hits"] / 4) * 50 + scored["ml_score"] * 50
    ).clip(0, 100).round(1)

    scored["risk_level"] = pd.cut(
        scored["risk_score"],
        bins=[0, 30, 60, 100],
        labels=["Low", "Medium", "High"],
        include_lowest=True,
    ).astype(str)

    scored["prediction"] = (
        scored["risk_score"] >= 50
    ).map({True: "TUNNEL", False: "normal"})

    return scored


# ===========================================================================
# Section 4 – Reporting (offline mode)
# ===========================================================================

def print_report(df: pd.DataFrame, tracker: TunnelIPTracker) -> None:
    """Print a console summary of the analysis results, then tunnel IPs."""
    print("\n" + "=" * 72)
    print("DNS TUNNELING DETECTION REPORT")
    print(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)

    if df.empty:
        print("\nNo DNS queries found. Nothing to score.")
        print("=" * 72 + "\n")
        return

    total_queries = len(df)
    high   = int((df["risk_level"] == "High").sum())
    medium = int((df["risk_level"] == "Medium").sum())
    low    = int((df["risk_level"] == "Low").sum())
    tunnel = int((df["prediction"] == "TUNNEL").sum())

    print("\nTraffic Summary")
    print(SEPARATOR)
    print(f"Total DNS queries analysed : {total_queries}")
    print(f"Unique source IPs          : {df['src_ip'].nunique()}")
    print(f"Flagged as TUNNEL          : {tunnel} ({(tunnel/total_queries)*100:.1f}%)")
    print(f"High risk queries          : {high}")
    print(f"Medium risk queries        : {medium}")
    print(f"Low risk queries           : {low}")

    print("\nPer-IP Summary")
    print(SEPARATOR)
    per_ip = (
        df.groupby("src_ip")
        .agg(
            queries =("query",      "count"),
            max_risk=("risk_score", "max"),
            avg_risk=("risk_score", "mean"),
            tunnels =("prediction", lambda v: (v == "TUNNEL").sum()),
        )
        .sort_values("max_risk", ascending=False)
    )
    print(f"{'IP':<17} {'Queries':>7} {'Max Risk':>9} {'Avg Risk':>9} {'Tunnels':>8}")
    print(f"{'-'*17} {'-'*7} {'-'*9} {'-'*9} {'-'*8}")
    for ip, row in per_ip.iterrows():
        flag = "  *** TUNNEL SOURCE ***" if row["max_risk"] >= 60 else ""
        print(
            f"{ip:<17} {int(row['queries']):>7} {row['max_risk']:>9.1f} "
            f"{row['avg_risk']:>9.1f} {int(row['tunnels']):>8}{flag}"
        )

    print("\nTop High-Risk Alerts")
    print(SEPARATOR)
    top_alerts = (
        df[df["risk_level"] == "High"]
        .sort_values("risk_score", ascending=False)
        .head(10)
    )
    if top_alerts.empty:
        print("No high-risk alerts were produced for this capture.")
    else:
        for _, row in top_alerts.iterrows():
            query_text    = row["query"]
            display_query = query_text[:72] + ("..." if len(query_text) > 72 else "")
            print(f"\n[{row['risk_score']:5.1f}] {row['src_ip']:<16} {row['record_type']}")
            print(f"Query      : {display_query}")
            print(
                f"Subdomain  : {int(row['subdomain_length'])} chars   "
                f"Entropy: {row['subdomain_entropy']:.2f}   "
                f"Hex ratio: {row['hex_ratio']:.2f}   "
                f"Response: {int(row['response_size'])} bytes"
            )
            reasons = row["rule_reasons"]
            if reasons:
                for reason in reasons:
                    print(f"Reason     : {reason}")
            else:
                print("Reason     : Elevated by anomaly model (no rule threshold breach).")

    print("\nDetection Method")
    print(SEPARATOR)
    print("Rule-based thresholds contribute 50% of the final score:")
    for name, threshold in THRESHOLDS.items():
        print(f"  {name:<28} > {threshold}")
    print("Isolation Forest contributes the remaining 50%.")
    print("Queries with risk_score >= 50 are labelled TUNNEL.")
    print("=" * 72 + "\n")

    # Print tunnel IP registry after the main report
    tracker.print_summary()


# ===========================================================================
# Section 5 – Real-time scoring helpers
# ===========================================================================

def _purge_old_window(window: collections.deque, cutoff_ts: float) -> None:
    """Remove entries older than *cutoff_ts* from the left of the deque."""
    while window and window[0]["ts"] < cutoff_ts:
        window.popleft()


def _score_window(window_records: list[dict]) -> Optional[pd.Series]:
    """Run the full feature + detect pipeline on a list of records.
    Returns the last row (most recent packet) as a Series, or None."""
    features = extract_features(window_records)
    if features.empty:
        return None
    scored = detect(features)
    if scored.empty:
        return None
    # Return the row corresponding to the newest record
    return scored.iloc[-1]


def _handle_high_risk_realtime(
    row: pd.Series,
    tracker: TunnelIPTracker,
    cooldown_map: dict[str, float],
    notify_enabled: bool,
) -> None:
    """Update tracker and (optionally) fire a desktop popup for a high-risk row."""
    ip         = row["src_ip"]
    query      = row["query"]
    risk_score = row["risk_score"]
    reasons    = row.get("rule_reasons", []) or []

    is_new = tracker.flag(ip, query, risk_score, reasons)

    if not notify_enabled:
        return

    now = time.time()
    last_notif = cooldown_map.get(ip, 0.0)
    if now - last_notif < NOTIFICATION_COOLDOWN_SECONDS:
        return   # respect per-IP cooldown

    cooldown_map[ip] = now
    new_tag = " [NEW TUNNEL SOURCE]" if is_new else ""
    title   = f"⚠️ DNS Tunnel Detected — {ip}{new_tag}"
    body    = (
        f"Risk Score : {risk_score:.1f} / 100\n"
        f"Query      : {query[:80]}\n"
        f"{reasons[0] if reasons else 'Flagged by anomaly model.'}"
    )
    _notify_async(title, body)


# ===========================================================================
# Section 6 – Live capture mode
# ===========================================================================

def live_capture_mode(
    interface: str,
    window_seconds: int = LIVE_WINDOW_SECONDS_DEFAULT,
    notify_enabled: bool = True,
    dashboard_url: str = DASHBOARD_URL_DEFAULT,
    dashboard_enabled: bool = True,
) -> None:
    """Sniff DNS packets live and score each one in real time.

    Architecture
    ------------
    - A per-IP sliding window (deque) holds the last *window_seconds* of that
      IP's queries.  Old entries are purged on every new packet.
    - On each inbound DNS query we append the record to the sender's window,
      then re-run feature extraction + IsolationForest on the entire window.
      This gives accurate behavioural features that evolve as traffic grows.
    - When a packet scores as High-risk the TunnelIPTracker is updated and,
      if *notify_enabled*, a desktop popup is raised (max once per IP per
      NOTIFICATION_COOLDOWN_SECONDS seconds).
    - Every scored packet is pushed asynchronously to the DNS Shield dashboard
      via DashboardPusher (non-blocking — capture is never delayed).
    """
    if not SCAPY_AVAILABLE:
        print(
            "Error: scapy is required for live capture.\n"
            "  Install with:  pip install scapy\n"
            "  On Linux you may also need: sudo setcap cap_net_raw+ep $(which python3)"
        )
        sys.exit(1)

    tracker: TunnelIPTracker           = TunnelIPTracker()
    ip_windows: dict[str, collections.deque] = collections.defaultdict(collections.deque)
    cooldown_map: dict[str, float]     = {}
    live_stats = {"total": 0, "high": 0, "medium": 0, "low": 0, "tunnel": 0}

    # Dashboard pusher — non-blocking background thread
    pusher = DashboardPusher(
        base_url=dashboard_url,
        enabled=dashboard_enabled,
        interface=interface,
        window_seconds=window_seconds,
    )

    print("\n" + "=" * 72)
    print("DNS Tunnel Detector  —  LIVE CAPTURE MODE")
    print(f"Interface    : {interface}")
    print(f"Sliding window: {window_seconds} seconds")
    print(f"Desktop alerts: {'ON' if notify_enabled else 'OFF'}")
    print(f"Dashboard push: {'ON → ' + dashboard_url if dashboard_enabled else 'OFF'}")
    print(f"Started      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)
    print(
        f"\n  {'Time':<10} {'Level':<7} {'Src IP':<17} {'Type':<6} "
        f"{'Score':>6}  Query"
    )
    print(f"  {'-'*10} {'-'*7} {'-'*17} {'-'*6} {'-'*6}  {'-'*40}")

    def handle_packet(pkt) -> None:  # noqa: ANN001
        # We only care about outgoing DNS queries (QR=0, dport=53)
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return
        dns_layer = pkt[DNS]
        if dns_layer.qr != 0:        # skip responses
            return
        if pkt[UDP].dport != 53:     # skip non-standard DNS ports
            return
        if not dns_layer.qd:         # no question section
            return

        try:
            raw_qname = dns_layer.qd.qname
            query     = (
                raw_qname.decode("ascii", errors="replace").rstrip(".")
                if isinstance(raw_qname, bytes) else str(raw_qname).rstrip(".")
            )
        except Exception:
            return

        qtype_raw = dns_layer.qd.qtype
        qtype     = QTYPE_MAP.get(qtype_raw, str(qtype_raw))
        now_ts    = time.time()

        record: dict = {
            "ts":            now_ts,
            "src_ip":        pkt[IP].src,
            "dst_ip":        pkt[IP].dst,
            "sport":         pkt[UDP].sport,
            "query":         query.lower(),
            "record_type":   qtype,
            "response_size": 80,   # responses not tracked in live mode
        }

        src_ip = record["src_ip"]
        window = ip_windows[src_ip]

        # Purge stale entries, then add the new record
        _purge_old_window(window, now_ts - window_seconds)
        window.append(record)

        # Score against the full window for this IP
        scored_row = _score_window(list(window))
        if scored_row is None:
            return

        risk_score = scored_row["risk_score"]
        risk_level = str(scored_row["risk_level"])
        prediction = str(scored_row["prediction"])

        live_stats["total"] += 1
        live_stats[risk_level.lower()] = live_stats.get(risk_level.lower(), 0) + 1
        if prediction == "TUNNEL":
            live_stats["tunnel"] += 1

        # Console output
        level_tag = f"[{risk_level.upper()[:3]}]"
        ts_str    = datetime.datetime.now().strftime("%H:%M:%S")
        print(
            f"  {ts_str:<10} {level_tag:<7} {src_ip:<17} {qtype:<6} "
            f"{risk_score:6.1f}  {query[:60]}"
        )

        # Push to dashboard (non-blocking — runs in background thread)
        pusher.push_event(scored_row, tracker)

        # Handle high-risk: tracker + optional popup
        if risk_level == "High":
            _handle_high_risk_realtime(
                scored_row, tracker, cooldown_map, notify_enabled
            )

    try:
        _scapy_sniff(
            iface=interface,
            filter="udp port 53",
            prn=handle_packet,
            store=False,
        )
    except PermissionError:
        print(
            "\nPermission denied. Run as root or grant cap_net_raw:\n"
            "  sudo python pcap_detector.py --live --iface eth0"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    # ── Session summary ──────────────────────────────────────────────────
    print(f"\n\n{'='*72}")
    print("LIVE SESSION SUMMARY")
    print(f"{'='*72}")
    print(f"Total DNS queries seen : {live_stats['total']}")
    print(f"High risk              : {live_stats.get('high', 0)}")
    print(f"Medium risk            : {live_stats.get('medium', 0)}")
    print(f"Low risk               : {live_stats.get('low', 0)}")
    print(f"Flagged as TUNNEL      : {live_stats['tunnel']}")
    tracker.print_summary()


# ===========================================================================
# Section 7 – Offline pipeline helpers
# ===========================================================================

def _apply_offline_alerts(df: pd.DataFrame, tracker: TunnelIPTracker, notify_enabled: bool) -> None:
    """Walk high-risk rows, update tracker, send notifications for offline mode."""
    cooldown_map: dict[str, float] = {}
    high_rows = df[df["risk_level"] == "High"].sort_values("risk_score", ascending=False)
    for _, row in high_rows.iterrows():
        _handle_high_risk_realtime(row, tracker, cooldown_map, notify_enabled)


def build_output_path(pcap_path: str | Path) -> Path:
    """Create the CSV output path beside the capture file."""
    capture_path = Path(pcap_path)
    return capture_path.with_name(f"{capture_path.stem}_results.csv")


# ===========================================================================
# Section 8 – CLI
# ===========================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect DNS tunnelling in a PCAP file or via live capture.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pcap_detector.py capture.pcap
  python pcap_detector.py capture.pcap --no-notify
  python pcap_detector.py --live --iface eth0
  python pcap_detector.py --live --iface eth0 --window 120 --no-notify
        """,
    )
    parser.add_argument(
        "pcap_path",
        nargs="?",
        default="dns_tunneling_demo.pcap",
        help="Path to PCAP file (offline mode, default: dns_tunneling_demo.pcap).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Enable live capture mode (requires scapy and root/cap_net_raw).",
    )
    parser.add_argument(
        "--iface",
        default="eth0",
        help="Network interface for live capture (default: eth0).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=LIVE_WINDOW_SECONDS_DEFAULT,
        metavar="SECONDS",
        help=(
            f"Sliding window size for live mode in seconds "
            f"(default: {LIVE_WINDOW_SECONDS_DEFAULT})."
        ),
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Suppress desktop popup notifications.",
    )
    parser.add_argument(
        "--dashboard",
        default=DASHBOARD_URL_DEFAULT,
        metavar="URL",
        help=(
            f"DNS Shield dashboard base URL for real-time event streaming "
            f"(default: {DASHBOARD_URL_DEFAULT})."
        ),
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable streaming to the DNS Shield dashboard.",
    )
    return parser.parse_args()


# ===========================================================================
# Section 9 – Entry point
# ===========================================================================

def main() -> int:
    args = parse_args()
    notify_enabled    = not args.no_notify
    dashboard_enabled = not args.no_dashboard
    dashboard_url     = args.dashboard

    if args.live:
        # ── Live mode ─────────────────────────────────────────────────────
        live_capture_mode(
            interface=args.iface,
            window_seconds=args.window,
            notify_enabled=notify_enabled,
            dashboard_url=dashboard_url,
            dashboard_enabled=dashboard_enabled,
        )
        return 0

    # ── Offline mode ───────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("DNS Tunnelling Detector  —  OFFLINE PCAP MODE")
    print("=" * 72)

    tracker = TunnelIPTracker()

    records  = parse_pcap(args.pcap_path)

    print("[2/4] Extracting features")
    features = extract_features(records)

    print("[3/4] Running detection")
    results  = detect(features)

    print("[4/4] Building report & dispatching alerts")
    if notify_enabled:
        _apply_offline_alerts(results, tracker, notify_enabled=True)
    else:
        # Still populate tracker even without popups
        _apply_offline_alerts(results, tracker, notify_enabled=False)

    print_report(results, tracker)

    output_path = build_output_path(args.pcap_path)
    results.reindex(columns=OUTPUT_COLUMNS).sort_values(
        "risk_score", ascending=False
    ).to_csv(output_path, index=False)
    print(f"Saved analysis CSV to: {output_path}")

    # Push full result set to dashboard (offline batch mode)
    if dashboard_enabled:
        pcap_name = str(Path(args.pcap_path).name)
        pusher = DashboardPusher(
            base_url=dashboard_url,
            enabled=True,
            interface=f"offline:{pcap_name}",
            window_seconds=0,
        )
        print(f"[5/5] Pushing results to dashboard at {dashboard_url} …")
        pusher.push_batch(results, tracker, pcap_name=pcap_name)
        print("      Done.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as exc:
        print(f"\nError: {exc}")
        raise SystemExit(1) from exc
    except ValueError as exc:
        print(f"\nInput error: {exc}")
        raise SystemExit(1) from exc
    except Exception as exc:
        print(f"\nUnexpected failure: {exc}")
        raise SystemExit(1) from exc