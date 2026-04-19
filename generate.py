"""
NetSentinel — DNS Traffic Generator
=====================================
Generates realistic DNS traffic (normal + tunnel-like) for testing
pcap_detector.py in live mode.

Usage
-----
  # Default mixed mode (300 packets)
  sudo python generate.py

  # Gradual escalation demo (matches slide presentation)
  sudo python generate.py --mode escalate

  # Tunnel-only traffic
  sudo python generate.py --mode tunnel --packets 100

  # Burst from single attacker IP
  sudo python generate.py --mode burst --packets 120 --delay 0.1

  # Normal benign baseline only
  sudo python generate.py --mode normal --packets 100

Dependencies
------------
  pip install scapy
"""

import argparse
import base64
import random
import string
import time

try:
    from scapy.all import DNS, DNSQR, IP, UDP, send
except ImportError:
    print("  [ERROR] Scapy not found. Install with: pip install scapy")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Domain pools
# ---------------------------------------------------------------------------

NORMAL_DOMAINS = [
    "google.com", "youtube.com", "github.com", "stackoverflow.com",
    "amazon.com", "cloudflare.com", "microsoft.com", "apple.com",
    "reddit.com", "wikipedia.org", "netflix.com", "twitter.com",
    "linkedin.com", "dropbox.com", "slack.com",
]

TUNNEL_C2_ROOTS = [
    "tunnel.evil.io", "c2.malware.net", "exfil.badguy.com",
    "dns-tunnel.xyz", "data.leak.org", "hiddendata.pw",
]

TUNNEL_QTYPES = ["TXT", "NULL", "MX", "CNAME", "NS"]
NORMAL_QTYPES = ["A", "AAAA"]

ATTACKER_IPS = [
    f"10.0.{random.randint(0,9)}.{random.randint(2,253)}" for _ in range(5)
]

# ---------------------------------------------------------------------------
# Session-level counters
# ---------------------------------------------------------------------------

_stats = {"normal": 0, "tunnel": 0, "burst": 0, "total": 0}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_ip() -> str:
    pool = random.randint(0, 2)
    if pool == 0:
        return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,253)}"
    elif pool == 1:
        return f"172.{random.randint(16,31)}.{random.randint(0,254)}.{random.randint(1,253)}"
    else:
        return f"192.168.{random.randint(0,254)}.{random.randint(1,253)}"


def fake_b64_payload(size_bytes: int = 24) -> str:
    raw = bytes(random.randint(0, 255) for _ in range(size_bytes))
    return base64.b64encode(raw).decode().replace("=", "").replace("+", "x").replace("/", "y")


def chunked_tunnel_domain(root: str) -> str:
    chunk1 = fake_b64_payload(12)
    chunk2 = fake_b64_payload(8)
    seq    = random.randint(0, 99)
    return f"{chunk1}.{chunk2}.seq{seq}.{root}"


def normal_subdomain_domain() -> str:
    domain = random.choice(NORMAL_DOMAINS)
    sub    = random.choice(["www", "api", "cdn", "mail", "static", "assets", ""])
    return f"{sub}.{domain}".lstrip(".")


# ---------------------------------------------------------------------------
# Packet sender
# ---------------------------------------------------------------------------

def send_dns(src_ip: str, domain: str, qtype: str = "A", dst: str = "8.8.8.8") -> None:
    pkt = (
        IP(src=src_ip, dst=dst) /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    )
    send(pkt, verbose=False)


def log(label: str, src_ip: str, qtype: str, domain: str, kind: str = "normal") -> None:
    ts = time.strftime("%H:%M:%S")
    if kind == "tunnel":
        color = RED
        tag   = f"{RED}[TUNNEL]{RESET}"
    elif kind == "burst":
        color = YELLOW
        tag   = f"{YELLOW}[BURST ]{RESET}"
    else:
        color = GREEN
        tag   = f"{GREEN}[NORMAL]{RESET}"

    domain_display = domain[:60] + "..." if len(domain) > 60 else domain
    print(
        f"  {DIM}[{ts}]{RESET} {tag} "
        f"{CYAN}{src_ip:<17}{RESET} "
        f"{WHITE}{qtype:<6}{RESET} "
        f"{color}{domain_display}{RESET}"
    )
    _stats["total"] += 1


def print_phase_header(phase: str, description: str, count: int, color: str = WHITE) -> None:
    line = "─" * 68
    print(f"\n  {color}{BOLD}{line}{RESET}")
    print(f"  {color}{BOLD}  {phase}{RESET}")
    print(f"  {DIM}  {description}  |  {count} packets{RESET}")
    print(f"  {color}{BOLD}{line}{RESET}")


def print_phase_summary(label: str, sent: int, tunnels: int = 0) -> None:
    normal_count = sent - tunnels
    print(f"\n  {DIM}  ┌─ Phase complete: {sent} packets sent{RESET}")
    if tunnels > 0:
        print(f"  {DIM}  ├─ Tunnel queries : {RED}{tunnels}{RESET}")
        print(f"  {DIM}  └─ Normal queries : {GREEN}{normal_count}{RESET}")
    else:
        print(f"  {DIM}  └─ All queries    : {GREEN}{sent} normal{RESET}")


# ---------------------------------------------------------------------------
# Traffic modes
# ---------------------------------------------------------------------------

def send_normal(count: int, delay: float) -> None:
    sent = 0
    for _ in range(count):
        src    = random_ip()
        domain = normal_subdomain_domain()
        qtype  = random.choice(NORMAL_QTYPES)
        send_dns(src, domain, qtype)
        log("NORMAL", src, qtype, domain, "normal")
        _stats["normal"] += 1
        sent += 1
        time.sleep(delay)
    print_phase_summary("Normal", sent)


def send_tunnel(count: int, delay: float) -> None:
    sent = 0
    for _ in range(count):
        src    = random.choice(ATTACKER_IPS)
        root   = random.choice(TUNNEL_C2_ROOTS)
        domain = chunked_tunnel_domain(root)
        qtype  = random.choice(TUNNEL_QTYPES)
        send_dns(src, domain, qtype)
        log("TUNNEL", src, qtype, domain, "tunnel")
        _stats["tunnel"] += 1
        sent += 1
        time.sleep(delay)
    print_phase_summary("Tunnel", sent, sent)


def send_burst(attacker_ip: str, count: int, delay: float) -> None:
    sent    = 0
    root    = random.choice(TUNNEL_C2_ROOTS)
    for i in range(count):
        domain = chunked_tunnel_domain(root)
        qtype  = random.choice(TUNNEL_QTYPES)
        send_dns(attacker_ip, domain, qtype)
        log(f"BURST[{i+1}]", attacker_ip, qtype, domain, "burst")
        _stats["burst"] += 1
        _stats["tunnel"] += 1
        sent += 1
        time.sleep(delay)
    print_phase_summary("Burst", sent, sent)


def send_mixed(count: int, delay: float, tunnel_ratio: float = 0.4) -> None:
    sent    = 0
    tunnels = 0
    for _ in range(count):
        if random.random() < tunnel_ratio:
            src    = random.choice(ATTACKER_IPS)
            root   = random.choice(TUNNEL_C2_ROOTS)
            domain = chunked_tunnel_domain(root)
            qtype  = random.choice(TUNNEL_QTYPES)
            send_dns(src, domain, qtype)
            log("TUNNEL", src, qtype, domain, "tunnel")
            _stats["tunnel"] += 1
            tunnels += 1
        else:
            src    = random_ip()
            domain = normal_subdomain_domain()
            qtype  = random.choice(NORMAL_QTYPES)
            send_dns(src, domain, qtype)
            log("NORMAL", src, qtype, domain, "normal")
            _stats["normal"] += 1
        sent += 1
        time.sleep(delay)
    print_phase_summary("Mixed", sent, tunnels)


def send_escalate(delay: float) -> None:
    """
    3-phase escalation demo matching the presentation slides:
      Phase 1 — 100 normal queries  (baseline, all green)
      Phase 2 — 80  mixed queries   (50% tunnel, suspicion builds)
      Phase 3 — 120 burst queries   (single attacker IP, triggers High-risk)
    Total: 300 packets
    """
    attacker = random.choice(ATTACKER_IPS)

    print_phase_header(
        "PHASE 1 / 3 — Normal Baseline",
        "Benign DNS traffic only. Detector should report LOW risk.",
        100, GREEN
    )
    send_normal(100, delay)

    print_phase_header(
        "PHASE 2 / 3 — Mixed Traffic",
        "50% tunnel queries introduced. Detector should report MEDIUM risk.",
        80, YELLOW
    )
    send_mixed(80, delay, tunnel_ratio=0.5)

    print_phase_header(
        "PHASE 3 / 3 — Rapid Burst",
        f"Attacker {attacker} exfiltrating fast. Detector should report HIGH risk.",
        120, RED
    )
    send_burst(attacker, 120, max(delay * 0.2, 0.05))

    # Escalation summary
    total_tunnel = _stats["tunnel"]
    total_normal = _stats["normal"]
    line = "═" * 68
    print(f"\n  {CYAN}{BOLD}{line}{RESET}")
    print(f"  {CYAN}{BOLD}  ESCALATION COMPLETE — SESSION SUMMARY{RESET}")
    print(f"  {line}")
    print(f"  {WHITE}  Total packets sent : {BOLD}{_stats['total']}{RESET}")
    print(f"  {GREEN}  Normal queries     : {total_normal}{RESET}")
    print(f"  {RED}  Tunnel queries     : {total_tunnel}{RESET}")
    print(f"  {YELLOW}  Burst packets      : {_stats['burst']}{RESET}")
    print(f"  {DIM}  Expected detector  : LOW → MEDIUM → HIGH risk progression{RESET}")
    print(f"  {CYAN}{BOLD}{line}{RESET}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetSentinel DNS Traffic Generator — for testing pcap_detector.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  mixed     Normal + tunnel traffic blend (default)
  normal    Benign DNS queries only
  tunnel    Tunnel-like queries only
  burst     Rapid exfiltration from a single attacker IP
  escalate  3-phase demo: normal → mixed → burst  [recommended for demo]

Examples:
  sudo python generate.py --mode escalate
  sudo python generate.py --mode burst --packets 120 --delay 0.1
  sudo python generate.py --mode mixed --packets 300 --iface eth0
        """,
    )
    parser.add_argument(
        "--mode",
        choices=["mixed", "normal", "tunnel", "burst", "escalate"],
        default="mixed",
        help="Traffic generation mode (default: mixed)"
    )
    parser.add_argument(
        "--packets", type=int, default=300,
        help="Total packets to send, non-escalate modes (default: 300)"
    )
    parser.add_argument(
        "--delay", type=float, default=0.3,
        help="Seconds between packets (default: 0.3)"
    )
    parser.add_argument(
        "--iface", default="lo",
        help="Network interface (default: lo)"
    )
    return parser.parse_args()


def print_session_summary(mode: str) -> None:
    if mode == "escalate":
        return  # escalate prints its own summary
    total_tunnel = _stats["tunnel"]
    total_normal = _stats["normal"]
    line = "═" * 68
    print(f"\n  {CYAN}{BOLD}{line}{RESET}")
    print(f"  {CYAN}{BOLD}  SESSION COMPLETE{RESET}")
    print(f"  {line}")
    print(f"  {WHITE}  Total packets sent : {BOLD}{_stats['total']}{RESET}")
    print(f"  {GREEN}  Normal queries     : {total_normal}{RESET}")
    if total_tunnel > 0:
        print(f"  {RED}  Tunnel queries     : {total_tunnel}{RESET}")
    print(f"  {DIM}  Check pcap_detector output and Wireshark for results.{RESET}")
    print(f"  {CYAN}{BOLD}{line}{RESET}\n")


def main() -> None:
    args = parse_args()

    line = "═" * 68
    print(f"\n  {CYAN}{BOLD}{line}{RESET}")
    print(f"  {CYAN}{BOLD}  NetSentinel — DNS Traffic Generator v1.0{RESET}")
    print(f"  {line}")
    print(f"  {WHITE}  Mode      : {BOLD}{args.mode.upper()}{RESET}")
    print(f"  {WHITE}  Interface : {args.iface}{RESET}")
    if args.mode == "escalate":
        print(f"  {WHITE}  Packets   : 300 total  (Phase 1: 100 | Phase 2: 80 | Phase 3: 120){RESET}")
        print(f"  {WHITE}  Est. time : ~{int(100*args.delay + 80*args.delay + 120*args.delay*0.2)}s{RESET}")
    else:
        print(f"  {WHITE}  Packets   : {args.packets}  |  Delay: {args.delay}s  |  Est: ~{int(args.packets*args.delay)}s{RESET}")
    print(f"  {CYAN}{line}{RESET}")
    print(f"\n  {DIM}  Time       Type      Src IP             QType  Domain{RESET}")
    print(f"  {DIM}  {'─'*9}  {'─'*7}  {'─'*17}  {'─'*5}  {'─'*35}{RESET}")

    try:
        if args.mode == "normal":
            print_phase_header("NORMAL MODE", "Sending benign DNS baseline traffic", args.packets, GREEN)
            send_normal(args.packets, args.delay)
        elif args.mode == "tunnel":
            print_phase_header("TUNNEL MODE", "Sending high-entropy tunnel queries only", args.packets, RED)
            send_tunnel(args.packets, args.delay)
        elif args.mode == "burst":
            attacker = random.choice(ATTACKER_IPS)
            print_phase_header("BURST MODE", f"Single attacker {attacker} exfiltrating rapidly", args.packets, YELLOW)
            send_burst(attacker, args.packets, args.delay)
        elif args.mode == "escalate":
            send_escalate(args.delay)
        else:  # mixed
            pct = 40
            print_phase_header("MIXED MODE", f"{pct}% tunnel + {100-pct}% normal traffic blend", args.packets, CYAN)
            send_mixed(args.packets, args.delay, tunnel_ratio=0.4)

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}  Stopped by user (Ctrl-C).{RESET}")

    print_session_summary(args.mode)


if __name__ == "__main__":
    main()