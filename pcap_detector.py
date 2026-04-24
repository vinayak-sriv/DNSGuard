"""
DNSGuard detector.

The detector supports offline PCAP analysis and live DNS capture. It extracts
lexical and per-source behavioural features, combines rule thresholds with an
Isolation Forest anomaly score, and can stream scored events to the Flask
dashboard.

Usage
-----
  # Offline (unchanged interface):
  python pcap_detector.py capture.pcap

  # Live capture (requires scapy and raw-packet privileges):
  python pcap_detector.py --live --iface eth0

  # Live with custom sliding window (seconds):
  python pcap_detector.py --live --iface eth0 --window 120

  # Live with dashboard streaming:
  python pcap_detector.py --live --iface eth0 --dashboard http://127.0.0.1:8080

  # Offline analysis with dashboard push:
  python pcap_detector.py capture.pcap --dashboard http://127.0.0.1:8080

  # Suppress desktop popups:
  python pcap_detector.py capture.pcap --no-notify

  # Suppress dashboard push:
  python pcap_detector.py --live --iface eth0 --no-dashboard

Dependencies
------------
  pip install pandas scikit-learn numpy   # core
  pip install scapy                       # live capture only
  pip install plyer                       # desktop notifications, optional
  pip install requests                    # dashboard streaming, optional
"""

from __future__ import annotations

import argparse
import collections
import datetime
import functools
import math
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import numpy as np
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
    1:  "A",
    2:  "NS",
    5:  "CNAME",
    6:  "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}

THRESHOLDS: dict[str, float] = {
    "subdomain_length":    45,
    "subdomain_entropy":   3.8,
    "query_rate_per_min":  5.0,
    "special_type_count":  10,
}

TOTAL_RULES: int = len(THRESHOLDS)

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
    "ts", "src_ip", "dst_ip", "sport", "query", "record_type",
    "response_size", "subdomain", "query_length", "subdomain_length",
    "subdomain_entropy", "dot_count", "digit_ratio", "hex_ratio",
    "is_special_type", "query_count", "unique_domains", "avg_qlen",
    "avg_entropy", "avg_response", "special_type_count",
    "query_rate_per_min", "rule_hits", "rule_reasons",
    "ml_score", "risk_score", "risk_level", "prediction",
]

OUTPUT_COLUMNS: list[str] = [
    "ts", "src_ip", "dst_ip", "sport", "query", "record_type",
    "response_size", "subdomain_length", "subdomain_entropy", "hex_ratio",
    "query_rate_per_min", "risk_score", "risk_level", "prediction",
]

SEPARATOR = "-" * 72
NOTIFICATION_COOLDOWN_SECONDS = 30    # minimum gap between popups per IP
LIVE_WINDOW_SECONDS_DEFAULT   = 300   # 5-minute sliding window for live mode
LIVE_ML_MIN_ROWS       = 24
LIVE_SIGNAL_HEX_RATIO  = 0.60
LIVE_SIGNAL_DIGIT_RATIO = 0.35

DASHBOARD_URL_DEFAULT  = "http://127.0.0.1:8080"
DASHBOARD_PUSH_TIMEOUT = 1     # seconds — never block packet capture
DASHBOARD_MAX_QUEUE    = 500   # drop oldest if queue grows beyond this
ETHERNET_LINKTYPE      = 1
OFFLINE_ML_MIN_ROWS    = 8
OFFLINE_ML_ESTIMATORS  = 128
LIVE_ML_ESTIMATORS     = 64
ML_MAX_SAMPLES         = 256
LIVE_TUNNEL_MIN_RULE_HITS = 2
LIVE_TUNNEL_SUSTAINED_WINDOW = 24
LIVE_TUNNEL_SUSTAINED_RISK_SCORE = 75.0

# Pre-compiled struct formats used in the hot PCAP parsing loop
_STRUCT_HDR   = struct.Struct("<IIII")   # little-endian pcap record header
_STRUCT_HDR_B = struct.Struct(">IIII")   # big-endian pcap record header
_STRUCT_ETH   = struct.Struct("!H")      # Ethernet type field
_STRUCT_PORTS = struct.Struct("!HH")     # UDP src/dst ports
_STRUCT_DNS2  = struct.Struct("!HHH")    # txid, flags, qdcount

# Pre-computed hex character set for fast membership test
_HEX_CHARS = frozenset("0123456789abcdef")
_MULTI_LABEL_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.uk",
        "co.in",
        "co.jp",
        "co.uk",
        "com.au",
        "com.br",
        "com.cn",
        "com.mx",
        "com.tr",
        "gov.uk",
        "net.au",
        "org.au",
        "org.uk",
    }
)
_COMMON_SECOND_LEVEL_DOMAINS = frozenset(
    {"ac", "co", "com", "edu", "gov", "mil", "net", "org"}
)


# ===========================================================================
# Tunnel IP tracker
# ===========================================================================

class TunnelIPTracker:
    """Thread-safe registry of IPs flagged as suspected DNS tunnel sources.

    Each time an IP produces a High-risk or TUNNEL-predicted query it is
    'flagged' here. The tracker records:
      - first_seen / last_seen timestamps
      - total number of flagged queries
      - peak risk score observed
      - up to five representative query samples
      - the union of all rule reasons that were triggered
    """

    __slots__ = ("_lock", "_tunnels")

    def __init__(self) -> None:
        self._lock    = threading.Lock()
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
            entry = self._tunnels.get(ip)
            is_new = entry is None
            if is_new:
                entry = {
                    "first_seen":     now,
                    "last_seen":      now,
                    "flagged_queries": 0,
                    "max_risk_score":  0.0,
                    "sample_queries":  [],
                    "reasons":         set(),
                }
                self._tunnels[ip] = entry
            entry["last_seen"] = now
            entry["flagged_queries"] += 1
            if risk_score > entry["max_risk_score"]:
                entry["max_risk_score"] = risk_score
            samples = entry["sample_queries"]
            if len(samples) < 5:
                samples.append(query)
            entry["reasons"].update(reasons)
            return is_new

    def get_all(self) -> dict[str, dict]:
        """Return a shallow snapshot of all tracked tunnel IPs."""
        with self._lock:
            # Shallow-copy each entry dict; callers must not mutate sets/lists
            return {ip: dict(info) for ip, info in self._tunnels.items()}

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._tunnels)

    def print_summary(self) -> None:
        """Print a formatted table of all identified tunnel IPs."""
        tunnels = self.get_all()
        print("\n" + "=" * 72)
        print("SUSPECTED TUNNEL SOURCE IPs")
        print("=" * 72)
        if not tunnels:
            print("  No tunnel source IPs were identified in this session.")
            print("=" * 72)
            return
        for ip, info in sorted(
            tunnels.items(),
            key=lambda kv: kv[1]["max_risk_score"],
            reverse=True,
        ):
            first = info["first_seen"].strftime("%Y-%m-%d %H:%M:%S")
            last  = info["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n  [SUSPECTED] {ip}")
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
# Dashboard streaming
# ===========================================================================

class DashboardPusher:
    """Non-blocking background worker that streams scored events to the
    DNSGuard dashboard (dashboard.py) via POST /live/push.

    Packet capture should not wait for dashboard I/O. Live events are queued
    and sent by a daemon thread; offline analysis sends one batch after the
    capture has been scored.
    """

    __slots__ = (
        "base_url", "enabled", "interface", "window_seconds",
        "_queue", "_warned", "_lock", "_event", "_worker",
    )

    def __init__(
        self,
        base_url: str = DASHBOARD_URL_DEFAULT,
        enabled: bool = True,
        interface: str = "",
        window_seconds: int = LIVE_WINDOW_SECONDS_DEFAULT,
    ) -> None:
        self.base_url       = base_url.rstrip("/")
        self.enabled        = enabled and REQUESTS_AVAILABLE
        self.interface      = interface
        self.window_seconds = window_seconds
        self._queue: collections.deque[dict] = collections.deque(maxlen=DASHBOARD_MAX_QUEUE)
        self._warned        = False
        self._lock          = threading.Lock()
        self._event         = threading.Event()

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

    def push_event(self, scored_row: pd.Series, tracker: TunnelIPTracker) -> None:
        """Enqueue a single scored row for async delivery. Never blocks."""
        if not self.enabled:
            return
        self._queue.append(self._build_event_payload(scored_row, tracker))
        self._event.set()   # wake the drain thread immediately

    def push_batch(
        self,
        results: pd.DataFrame,
        tracker: TunnelIPTracker,
        pcap_name: str = "",
    ) -> None:
        """Synchronously push an entire offline result set to the dashboard."""
        if not self.enabled or results.empty:
            return
        tracker_snap = self._tracker_snapshot(tracker)
        payload = {
            "events":         [self._row_to_dict(row) for _, row in results.iterrows()],
            "tracker":        tracker_snap,
            "interface":      f"offline:{pcap_name}" if pcap_name else "offline",
            "window_seconds": 0,
        }
        self._send(payload, label="batch")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_event_payload(self, row: pd.Series, tracker: TunnelIPTracker) -> dict:
        payload = {
            "event":          self._row_to_dict(row),
            "interface":      self.interface,
            "window_seconds": self.window_seconds,
        }
        if str(row.get("prediction", "")) == "TUNNEL":
            payload["tracker"] = self._tracker_snapshot(tracker)
        return payload

    @staticmethod
    def _row_to_dict(row: pd.Series) -> dict:
        """Convert a scored pandas Series to a JSON-safe dict."""
        out: dict = {}
        for k, v in row.items():
            # Unwrap numpy scalars
            if hasattr(v, "item"):
                try:
                    v = v.item()
                except Exception:
                    v = str(v)
            # Sanitise floats
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
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
        return {
            ip: {
                "first_seen":      str(info.get("first_seen", "")),
                "last_seen":       str(info.get("last_seen", "")),
                "flagged_queries": int(info.get("flagged_queries", 0)),
                "max_risk_score":  float(info.get("max_risk_score", 0.0)),
                "sample_queries":  list(info.get("sample_queries", [])),
                "reasons":         list(info.get("reasons", [])),
            }
            for ip, info in tracker.get_all().items()
        }

    def _send(self, payload: dict, label: str = "event") -> bool:
        """HTTP POST to /live/push. Returns True on success."""
        url = f"{self.base_url}/live/push"
        try:
            resp = _requests.post(url, json=payload, timeout=DASHBOARD_PUSH_TIMEOUT)
            if resp.status_code == 200:
                self._warned = False
                return True
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
        """Background thread: drain the queue; sleep via Event instead of polling."""
        while True:
            self._event.wait()           # block until push_event wakes us
            self._event.clear()
            while self._queue:
                try:
                    self._send(self._queue.popleft())
                except Exception:
                    pass


# ===========================================================================
# Desktop notifications
# ===========================================================================

def send_system_notification(title: str, message: str) -> None:
    """Dispatch a native desktop popup using the best available mechanism.

    Priority chain:
      1. plyer  (cross-platform Python library)
      2. notify-send  (Linux / freedesktop)
      3. osascript    (macOS)
      4. ctypes MessageBox (Windows fallback)
    """
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
            pass

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

    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x30 | 0x1000)
        except Exception:
            pass


def _notify_async(title: str, message: str) -> None:
    """Fire a notification in a daemon thread so capture is never blocked."""
    threading.Thread(
        target=send_system_notification,
        args=(title, message),
        daemon=True,
    ).start()


# ===========================================================================
# Section 3 – Core detection pipeline
# ===========================================================================

def _empty_feature_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=REPORT_COLUMNS)


def _registered_domain_label_count(labels: list[str]) -> int:
    """Best-effort suffix handling without pulling in a PSL dependency."""
    if len(labels) < 2:
        return len(labels)
    suffix2 = ".".join(labels[-2:]).lower()
    if suffix2 in _MULTI_LABEL_PUBLIC_SUFFIXES and len(labels) >= 3:
        return 3
    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and labels[-2].lower() in _COMMON_SECOND_LEVEL_DOMAINS
    ):
        return 3
    return 2


def _payload_subdomain(query: str) -> str:
    """Collapse all labels before the base domain into one payload string."""
    labels = [label for label in query.split(".") if label]
    if not labels:
        return ""
    registered_domain_labels = _registered_domain_label_count(labels)
    if len(labels) <= registered_domain_labels:
        return labels[0]
    return "".join(labels[:-registered_domain_labels])


def _parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS name from wire format (iterative, no recursion overhead)."""
    if depth > 10 or offset >= len(data):
        return "", offset

    labels: list[str] = []
    data_len = len(data)
    current_offset = offset
    followed_pointer = False

    while current_offset < data_len:
        length = data[current_offset]

        if length == 0:
            current_offset += 1
            break

        if (length & 0xC0) == 0xC0:
            # DNS compression pointer
            if current_offset + 1 >= data_len:
                return ".".join(labels), data_len
            pointer = ((length & 0x3F) << 8) | data[current_offset + 1]
            if not followed_pointer:
                # Only save the return offset on the first pointer follow
                return_offset = current_offset + 2
                followed_pointer = True
            # Follow the pointer in-place (iterative instead of recursive)
            if pointer >= data_len or depth > 10:
                break
            current_offset = pointer
            depth += 1
            continue

        current_offset += 1
        label_end = current_offset + length
        if label_end > data_len:
            return ".".join(labels), data_len

        labels.append(data[current_offset:label_end].decode("ascii", errors="replace"))
        current_offset = label_end

    final_offset = return_offset if followed_pointer else current_offset
    return ".".join(labels), final_offset


def parse_pcap(path: str | Path) -> list[dict]:
    """Parse a PCAP file and extract DNS query records."""
    capture_path = Path(path)
    if not capture_path.exists():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    print(f"[1/?] Reading packet capture: {capture_path}")
    magic_map = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
        b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
        b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }

    outstanding_queries: dict[tuple[str, int, str, int], dict] = {}
    records: list[dict] = []
    with capture_path.open("rb") as fh:
        global_header = fh.read(24)
        if len(global_header) < 24:
            raise ValueError("The file is too small to be a valid PCAP capture.")

        magic_bytes = global_header[:4]
        header_config = magic_map.get(magic_bytes)
        if header_config is None:
            raise ValueError(
                "Unsupported capture format. Expected a standard PCAP file "
                "(pcapng is not supported; convert with: editcap -F pcap input.pcapng out.pcap)."
            )
        endian, ts_scale = header_config

        hdr_struct = _STRUCT_HDR if endian == "<" else _STRUCT_HDR_B
        linktype = struct.unpack_from(f"{endian}I", global_header, 20)[0]
        if linktype != ETHERNET_LINKTYPE:
            raise ValueError(
                "Unsupported PCAP link type. Only Ethernet captures are currently supported."
            )

        while True:
            record_header = fh.read(16)
            if not record_header:
                break
            if len(record_header) < 16:
                break

            ts_sec, ts_usec, caplen, _origlen = hdr_struct.unpack(record_header)
            packet_bytes = fh.read(caplen)
            if len(packet_bytes) < caplen:
                break

            packet = memoryview(packet_bytes)
            pkt_len = len(packet)

            # Minimum viable: Ethernet(14) + IPv4-min(20) + UDP(8) = 42
            if pkt_len < 42:
                continue

            # Ethernet type — must be IPv4 (0x0800)
            if _STRUCT_ETH.unpack_from(packet, 12)[0] != 0x0800:
                continue

            ip_ihl = (packet[14] & 0x0F) * 4
            if ip_ihl < 20 or pkt_len < 14 + ip_ihl + 8:
                continue

            # Protocol — must be UDP (17)
            if packet[14 + 9] != 17:
                continue

            ip_raw = packet[14 + 12: 14 + 20]
            a, b, c, d, e, f, g, h = struct.unpack_from("8B", ip_raw)
            src_ip = f"{a}.{b}.{c}.{d}"
            dst_ip = f"{e}.{f}.{g}.{h}"

            udp_start = 14 + ip_ihl
            sport, dport = _STRUCT_PORTS.unpack_from(packet, udp_start)
            dns_start = udp_start + 8
            dns = packet[dns_start:]
            dns_len = pkt_len - dns_start

            if dns_len < 12:
                continue

            txid, flags, qdcount = _STRUCT_DNS2.unpack_from(dns, 0)

            if qdcount < 1:
                continue

            qr = (flags >> 15) & 1
            if not ((qr == 0 and dport == 53) or (qr == 1 and sport == 53)):
                continue

            dns_bytes = bytes(dns)
            qname, q_offset = _parse_dns_name(dns_bytes, 12)
            if not qname or q_offset + 4 > dns_len:
                continue

            qtype_raw = struct.unpack_from("!H", dns_bytes, q_offset)[0]
            qtype = QTYPE_MAP.get(qtype_raw, str(qtype_raw))

            if qr == 0:
                record: dict = {
                    "ts": ts_sec + ts_usec * ts_scale,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sport": sport,
                    "query": qname.lower(),
                    "record_type": qtype,
                    "response_size": 80,
                }
                outstanding_queries[(src_ip, sport, dst_ip, txid)] = record
                records.append(record)
            else:
                match_key = (dst_ip, dport, src_ip, txid)
                matched = outstanding_queries.pop(match_key, None)
                if matched is not None:
                    matched["response_size"] = pkt_len

    print(f"      Parsed {len(records)} DNS queries")
    return records


# ---------------------------------------------------------------------------
# Vectorized entropy helper (operates on an entire numpy array of strings)
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=8192)
def _entropy(text: str) -> float:
    """Shannon entropy of a single string (fast path for per-row use)."""
    if not text:
        return 0.0
    n = len(text)
    counts = np.frombuffer(text.encode(), dtype=np.uint8)
    _, cnts = np.unique(counts, return_counts=True)
    p = cnts / n
    return float(-np.dot(p, np.log2(p)))


def _series_entropy(series: pd.Series) -> pd.Series:
    """Vectorized Shannon entropy over a string Series using numpy."""
    # Fast path: compute character frequencies per string via numpy
    result = np.empty(len(series), dtype=np.float64)
    for i, text in enumerate(series):
        result[i] = _entropy(text)
    return pd.Series(result, index=series.index)


def extract_features(records: list[dict] | collections.deque) -> pd.DataFrame:
    """Build lexical and per-client behavioural features from parsed queries."""
    if not records:
        return _empty_feature_frame()

    df = pd.DataFrame(records)
    df["query"]       = df["query"].fillna("").astype(str)
    df["record_type"] = df["record_type"].fillna("UNKNOWN").astype(str)

    # ── Lexical features (fully vectorized) ──────────────────────────────────
    queries = df["query"]
    subdomains = pd.Series(
        [_payload_subdomain(query) for query in queries.tolist()],
        index=df.index,
    )

    df["subdomain"]        = subdomains
    df["query_length"]     = queries.str.len()
    df["subdomain_length"] = subdomains.str.len()
    df["dot_count"]        = queries.str.count(r"\.")

    # Entropy: still per-string but using numpy internally
    df["subdomain_entropy"] = _series_entropy(subdomains)

    # Digit ratio: vectorized with str accessor
    query_lengths = df["query_length"].clip(lower=1)
    digit_counts = queries.str.count(r"\d")
    df["digit_ratio"] = digit_counts / query_lengths

    # Hex ratio: vectorized character membership test
    sub_lower = subdomains.str.lower()
    sub_lengths = df["subdomain_length"].clip(lower=1)
    df["hex_ratio"] = sub_lower.str.count(r"[0-9a-f]") / sub_lengths

    df["is_special_type"] = df["record_type"].isin(["TXT", "NULL", "MX"]).astype(np.int8)

    # ── Behavioural (per-IP) features ────────────────────────────────────────
    client_features = (
        df.groupby("src_ip", sort=False)
        .agg(
            query_count      =("query",            "count"),
            unique_domains   =("query",            "nunique"),
            avg_qlen         =("query_length",     "mean"),
            avg_entropy      =("subdomain_entropy", "mean"),
            avg_response     =("response_size",    "mean"),
            special_type_count=("is_special_type", "sum"),
            first_ts         =("ts",               "min"),
            last_ts          =("ts",               "max"),
        )
        .assign(
            active_span_minutes=lambda g: np.maximum(
                (g["last_ts"] - g["first_ts"]) / 60.0,
                1.0 / 60.0,
            ),
            query_rate_per_min=lambda g: np.where(
                g["query_count"] > 1,
                (g["query_count"] - 1) / g["active_span_minutes"],
                0.0,
            ),
        )
        .drop(columns=["first_ts", "last_ts", "active_span_minutes"])
        .reset_index()
    )

    return df.merge(client_features, on="src_ip", how="left")


def _vectorized_rule_score(df: pd.DataFrame) -> pd.DataFrame:
    """Compute rule_hits and rule_reasons entirely in vectorized column ops.

    Avoids the extremely slow `df.apply(rule_score, axis=1)` pattern.
    """
    thr = THRESHOLDS

    long_sub   = df["subdomain_length"]   > thr["subdomain_length"]
    high_ent   = df["subdomain_entropy"]  > thr["subdomain_entropy"]
    high_rate  = df["query_rate_per_min"] > thr["query_rate_per_min"]
    many_spec  = df["special_type_count"] > thr["special_type_count"]
    suspicious_query = (
        long_sub
        | high_ent
        | (df["hex_ratio"] > LIVE_SIGNAL_HEX_RATIO)
        | (df["digit_ratio"] > LIVE_SIGNAL_DIGIT_RATIO)
        | df["is_special_type"].astype(bool)
    )
    high_rate_rule = high_rate & suspicious_query
    many_spec_rule = many_spec & suspicious_query

    df = df.copy()
    df["rule_hits"] = (
        long_sub.astype(int) + high_ent.astype(int) +
        high_rate_rule.astype(int) + many_spec_rule.astype(int)
    )

    # Build reason strings per row without Python-level apply
    reasons_list: list[list[str]] = [[] for _ in range(len(df))]
    idx = df.index.tolist()

    for i, (pos, row) in enumerate(zip(range(len(df)), df.itertuples(index=False))):
        r: list[str] = []
        if long_sub.iloc[i]:
            r.append(f"Subdomain is unusually long ({int(row.subdomain_length)} characters).")
        if high_ent.iloc[i]:
            r.append(f"Subdomain entropy is high ({row.subdomain_entropy:.2f}).")
        if high_rate_rule.iloc[i]:
            r.append(f"Source query rate is elevated ({row.query_rate_per_min:.1f}/min).")
        if many_spec_rule.iloc[i]:
            r.append(f"Source sent many TXT/NULL/MX queries ({int(row.special_type_count)}).")
        reasons_list[i] = r

    df["rule_reasons"] = reasons_list
    return df


def detect(
    df: pd.DataFrame,
    ml_min_rows: int = 2,
    ml_n_estimators: int = OFFLINE_ML_ESTIMATORS,
    ml_max_samples: int = ML_MAX_SAMPLES,
) -> pd.DataFrame:
    """Run rule-based and anomaly-based scoring on the feature frame."""
    if df.empty:
        return _empty_feature_frame()

    scored = _vectorized_rule_score(df)

    if len(scored) >= max(2, ml_min_rows):
        feature_matrix  = scored[ML_FEATURES].fillna(0).to_numpy(dtype=np.float64)
        scaled_features = StandardScaler().fit_transform(feature_matrix)
        max_samples = min(max(2, ml_max_samples), len(scored))
        model = IsolationForest(
            contamination=0.25,
            n_estimators=ml_n_estimators,
            max_samples=max_samples,
            random_state=42,
        )
        model.fit(scaled_features)
        raw_scores  = model.decision_function(scaled_features)
        score_min   = raw_scores.min()
        score_range = raw_scores.max() - score_min
        scored["ml_score"] = 1.0 - (raw_scores - score_min) / (score_range + 1e-9)
    else:
        scored["ml_score"] = 0.0

    scored["risk_score"] = (
        (scored["rule_hits"].to_numpy(dtype=np.float64) / TOTAL_RULES) * 50.0
        + scored["ml_score"].to_numpy(dtype=np.float64) * 50.0
    ).clip(0.0, 100.0).round(1)

    suspicious_shape = (
        (scored["subdomain_length"] > THRESHOLDS["subdomain_length"])
        | (scored["subdomain_entropy"] > THRESHOLDS["subdomain_entropy"])
        | (scored["hex_ratio"] > LIVE_SIGNAL_HEX_RATIO)
        | (scored["digit_ratio"] > LIVE_SIGNAL_DIGIT_RATIO)
    )
    supported_tunnel = (
        (scored["rule_hits"] >= 2)
        | ((scored["ml_score"] >= 0.75) & suspicious_shape)
    )
    unsupported_tunnel = (scored["risk_score"] >= 50.0) & ~supported_tunnel
    if unsupported_tunnel.any():
        adjusted_scores = scored["risk_score"].to_numpy(dtype=np.float64)
        adjusted_scores[unsupported_tunnel.to_numpy()] = np.minimum(
            adjusted_scores[unsupported_tunnel.to_numpy()],
            49.9,
        )
        scored["risk_score"] = np.round(adjusted_scores, 1)

    scored["risk_level"] = pd.cut(
        scored["risk_score"],
        bins=[0, 30, 60, 100],
        labels=["Low", "Medium", "High"],
        include_lowest=True,
    ).astype(str).replace("nan", "Low")

    scored["prediction"] = np.where(
        scored["risk_score"].to_numpy() >= 50.0, "TUNNEL", "normal"
    )

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
    tunnel_pct = f"{(tunnel / total_queries) * 100:.1f}%" if total_queries else "0.0%"

    print("\nTraffic Summary")
    print(SEPARATOR)
    print(f"Total DNS queries analysed : {total_queries}")
    print(f"Unique source IPs          : {df['src_ip'].nunique()}")
    print(f"Flagged as TUNNEL          : {tunnel} ({tunnel_pct})")
    print(f"High risk queries          : {high}")
    print(f"Medium risk queries        : {medium}")
    print(f"Low risk queries           : {low}")

    print("\nPer-IP Summary")
    print(SEPARATOR)
    per_ip = (
        df.groupby("src_ip", sort=False)
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
        flag = "  *** SUSPECTED TUNNEL SOURCE ***" if row["tunnels"] > 0 else ""
        print(
            f"{ip:<17} {int(row['queries']):>7} {row['max_risk']:>9.1f} "
            f"{row['avg_risk']:>9.1f} {int(row['tunnels']):>8}{flag}"
        )

    print("\nTop High-Risk Alerts")
    print(SEPARATOR)
    top_alerts = (
        df[df["risk_level"] == "High"]
        .nlargest(10, "risk_score")   # faster than sort_values().head()
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
            reasons = row["rule_reasons"] or []
            if not isinstance(reasons, list):
                reasons = [str(reasons)] if reasons else []
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

    tracker.print_summary()


# ===========================================================================
# Section 5 – Real-time scoring helpers
# ===========================================================================

def _purge_old_window(window: collections.deque, cutoff_ts: float) -> None:
    """Remove entries older than *cutoff_ts* from the left of the deque."""
    while window and window[0]["ts"] < cutoff_ts:
        window.popleft()


def _score_window(window: collections.deque) -> Optional[pd.Series]:
    """Run the full feature + detect pipeline on the current window deque.

    Passes the deque directly to extract_features to avoid an extra list copy.
    Returns the last row (most recent packet) as a Series, or None.
    """
    if not window:
        return None
    features = extract_features(window)
    if features.empty:
        return None
    latest_features = features.iloc[-1]
    use_ml = (
        len(window) >= LIVE_ML_MIN_ROWS
        and (
            float(latest_features.get("subdomain_length", 0.0)) > THRESHOLDS["subdomain_length"]
            or float(latest_features.get("subdomain_entropy", 0.0)) > THRESHOLDS["subdomain_entropy"]
            or float(latest_features.get("hex_ratio", 0.0)) > LIVE_SIGNAL_HEX_RATIO
            or float(latest_features.get("digit_ratio", 0.0)) > LIVE_SIGNAL_DIGIT_RATIO
        )
    )
    score_frame = features if use_ml else features.tail(1)
    scored = detect(
        score_frame,
        ml_min_rows=LIVE_ML_MIN_ROWS if use_ml else len(features) + 1,
        ml_n_estimators=LIVE_ML_ESTIMATORS,
        ml_max_samples=min(128, len(features)),
    )
    if scored.empty:
        return None
    latest = scored.iloc[-1].copy()

    if str(latest["prediction"]) == "TUNNEL":
        rule_hits = int(latest.get("rule_hits", 0) or 0)
        has_strong_rule_signal = rule_hits >= LIVE_TUNNEL_MIN_RULE_HITS
        has_sustained_high_score = (
            len(window) >= LIVE_TUNNEL_SUSTAINED_WINDOW
            and float(latest["risk_score"]) >= LIVE_TUNNEL_SUSTAINED_RISK_SCORE
        )
        if not has_strong_rule_signal and not has_sustained_high_score:
            latest["risk_score"] = min(float(latest["risk_score"]), 49.9)
            latest["risk_level"] = "Medium" if latest["risk_score"] >= 30.0 else "Low"
            latest["prediction"] = "normal"

    return latest


def _handle_detected_tunnel(
    row: pd.Series,
    tracker: TunnelIPTracker,
    cooldown_map: dict[str, float],
    notify_enabled: bool,
) -> None:
    """Update tracker and (optionally) fire a desktop popup for a tunnel row."""
    ip         = row["src_ip"]
    query      = row["query"]
    risk_score = float(row["risk_score"])
    reasons    = row.get("rule_reasons", []) or []
    if not isinstance(reasons, list):
        reasons = []

    is_new = tracker.flag(ip, query, risk_score, reasons)

    if not notify_enabled:
        return

    now = time.monotonic()
    if now - cooldown_map.get(ip, 0.0) < NOTIFICATION_COOLDOWN_SECONDS:
        return

    cooldown_map[ip] = now
    new_tag = " [NEW TUNNEL SOURCE]" if is_new else ""
    title   = f"DNS Tunnel Detected - {ip}{new_tag}"
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
    """Sniff DNS packets live and score each one in real time."""
    if not SCAPY_AVAILABLE:
        print(
            "Error: scapy is required for live capture.\n"
            "  Install with:  pip install scapy\n"
            "  On Linux you may also need: sudo setcap cap_net_raw+ep $(which python3)"
        )
        sys.exit(1)

    tracker: TunnelIPTracker = TunnelIPTracker()
    ip_windows: dict[str, collections.deque] = collections.defaultdict(collections.deque)
    ip_last_seen: dict[str, float] = {}
    cooldown_map: dict[str, float] = {}
    live_stats = {"total": 0, "high": 0, "medium": 0, "low": 0, "tunnel": 0}
    packet_counter = 0

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
    print(f"Dashboard push: {'ON -> ' + dashboard_url if dashboard_enabled else 'OFF'}")
    print(f"Started      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)
    print(
        f"\n  {'Time':<10} {'Level':<7} {'Src IP':<17} {'Type':<6} "
        f"{'Score':>6}  Query"
    )
    print(f"  {'-'*10} {'-'*7} {'-'*17} {'-'*6} {'-'*6}  {'-'*40}")

    def evict_idle_state(now_ts: float) -> None:
        stale_before = now_ts - max(float(window_seconds), NOTIFICATION_COOLDOWN_SECONDS)
        stale_ips = [
            ip for ip, last_seen in ip_last_seen.items()
            if last_seen < stale_before
        ]
        for stale_ip in stale_ips:
            ip_windows.pop(stale_ip, None)
            ip_last_seen.pop(stale_ip, None)
            cooldown_map.pop(stale_ip, None)

    def handle_packet(pkt) -> None:  # noqa: ANN001
        nonlocal packet_counter
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return
        dns_layer = pkt[DNS]
        if dns_layer.qr != 0 or pkt[UDP].dport != 53 or not dns_layer.qd:
            return

        try:
            raw_qname = dns_layer.qd.qname
            query = (
                raw_qname.decode("ascii", errors="replace").rstrip(".")
                if isinstance(raw_qname, bytes) else str(raw_qname).rstrip(".")
            )
        except Exception:
            return

        qtype_raw = dns_layer.qd.qtype
        qtype     = QTYPE_MAP.get(qtype_raw, str(qtype_raw))
        now_ts    = time.time()
        src_ip    = pkt[IP].src

        record: dict = {
            "ts":            now_ts,
            "src_ip":        src_ip,
            "dst_ip":        pkt[IP].dst,
            "sport":         pkt[UDP].sport,
            "query":         query.lower(),
            "record_type":   qtype,
            "response_size": 80,
        }

        window = ip_windows[src_ip]
        _purge_old_window(window, now_ts - window_seconds)
        window.append(record)
        ip_last_seen[src_ip] = now_ts
        packet_counter += 1

        if packet_counter % 200 == 0:
            evict_idle_state(now_ts)

        # Pass the deque directly — no list() copy needed
        scored_row = _score_window(window)
        if scored_row is None:
            return

        risk_score = float(scored_row["risk_score"])
        risk_level = str(scored_row["risk_level"])
        prediction = str(scored_row["prediction"])

        live_stats["total"] += 1
        live_stats[risk_level.lower()] = live_stats.get(risk_level.lower(), 0) + 1
        if prediction == "TUNNEL":
            live_stats["tunnel"] += 1

        ts_str    = datetime.datetime.now().strftime("%H:%M:%S")
        level_tag = f"[{risk_level.upper()[:3]}]"
        print(
            f"  {ts_str:<10} {level_tag:<7} {src_ip:<17} {qtype:<6} "
            f"{risk_score:6.1f}  {query[:60]}"
        )

        if prediction == "TUNNEL":
            _handle_detected_tunnel(scored_row, tracker, cooldown_map, notify_enabled)

        pusher.push_event(scored_row, tracker)

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

def _apply_offline_alerts(
    df: pd.DataFrame, tracker: TunnelIPTracker, notify_enabled: bool
) -> None:
    """Walk tunnel rows, update tracker, send notifications for offline mode."""
    cooldown_map: dict[str, float] = {}
    tunnel_rows = df[df["prediction"] == "TUNNEL"].nlargest(len(df), "risk_score")
    for _, row in tunnel_rows.iterrows():
        _handle_detected_tunnel(row, tracker, cooldown_map, notify_enabled)


def build_output_path(pcap_path: str | Path) -> Path:
    """Create the CSV output path beside the capture file."""
    capture_path = Path(pcap_path)
    return capture_path.with_name(f"{capture_path.stem}_results.csv")


# ===========================================================================
# Section 8 – CLI
# ===========================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect DNS tunneling in a PCAP file or via live capture.",
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
        default="samples/dns_tunneling_demo.pcap",
        help="Path to PCAP file (offline mode, default: samples/dns_tunneling_demo.pcap).",
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
        help=f"Sliding window size for live mode in seconds (default: {LIVE_WINDOW_SECONDS_DEFAULT}).",
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
        help=f"DNSGuard dashboard base URL (default: {DASHBOARD_URL_DEFAULT}).",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable streaming to the DNSGuard dashboard.",
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
        if args.window <= 0:
            raise ValueError("Live window must be a positive number of seconds.")
        live_capture_mode(
            interface=args.iface,
            window_seconds=args.window,
            notify_enabled=notify_enabled,
            dashboard_url=dashboard_url,
            dashboard_enabled=dashboard_enabled,
        )
        return 0

    # ── Offline mode ──────────────────────────────────────────────────────
    total_steps = 5 if dashboard_enabled else 4
    print("\n" + "=" * 72)
    print("DNS Tunneling Detector - OFFLINE PCAP MODE")
    print("=" * 72)

    tracker = TunnelIPTracker()
    records = parse_pcap(args.pcap_path)

    print(f"[2/{total_steps}] Extracting features")
    features = extract_features(records)

    print(f"[3/{total_steps}] Running detection")
    results  = detect(features, ml_min_rows=OFFLINE_ML_MIN_ROWS)

    print(f"[4/{total_steps}] Building report & dispatching alerts")
    _apply_offline_alerts(results, tracker, notify_enabled=notify_enabled)
    print_report(results, tracker)

    output_path = build_output_path(args.pcap_path)
    results.reindex(columns=OUTPUT_COLUMNS).nlargest(len(results), "risk_score").to_csv(
        output_path, index=False
    )
    print(f"Saved analysis CSV to: {output_path}")

    if dashboard_enabled:
        pcap_name = Path(args.pcap_path).name
        pusher = DashboardPusher(
            base_url=dashboard_url,
            enabled=True,
            interface=f"offline:{pcap_name}",
            window_seconds=0,
        )
        print(f"[5/{total_steps}] Pushing results to dashboard at {dashboard_url} …")
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
