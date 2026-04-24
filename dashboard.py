"""
DNSGuard dashboard.

Run with ``python dashboard.py`` and open http://127.0.0.1:8080.
The dashboard accepts offline PCAP uploads and live events from
``pcap_detector.py``.

How to connect pcap_detector.py (live mode) to this dashboard:
  Call POST /live/push with JSON:
    { "event": <scored_row_dict>, "tracker": <tracker.get_all() snapshot> }
  The dashboard surfaces new events in the Live Feed tab and updates the
  confirmed tunnel registry automatically.
"""
import datetime
import importlib.util
import math
import os
import tempfile
import threading
from ipaddress import ip_address
from pathlib import Path
from flask import Flask, jsonify, request, Response


def _env_int(name, default, minimum=1):
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(minimum, value)


def _coerce_positive_int(value, default, field_name):
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a positive integer") from exc
    if parsed <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return parsed


MAX_CONTENT_LENGTH = _env_int("DNS_SHIELD_MAX_UPLOAD_MB", 64) * 1024 * 1024
DEFAULT_UPLOAD_SUFFIX = ".pcap"
ALLOW_REMOTE = os.environ.get("DNS_SHIELD_ALLOW_REMOTE", "").strip() == "1"
MAX_PUSH_ROWS = _env_int("DNS_SHIELD_MAX_PUSH_ROWS", 50000)
MAX_TRACKER_ITEMS = _env_int("DNS_SHIELD_MAX_TRACKER_ITEMS", 1000)
MAX_LIVE_BATCH = _env_int("DNS_SHIELD_MAX_LIVE_BATCH", 200)
MAX_STORED_LIVE_EVENTS = _env_int("DNS_SHIELD_MAX_STORED_LIVE_EVENTS", 200)
MAX_VISIBLE_LIVE_EVENTS = _env_int("DNS_SHIELD_MAX_VISIBLE_LIVE_EVENTS", 100)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
_lock = threading.Lock()
_store = {
    "version": 0,
    "data": None,
    "pcap_name": "",
    "thresholds": {},
    "summary": {},
}

# Live-mode state — updated by POST /live/push from pcap_detector.py
_live_lock = threading.Lock()
_live_store = {
    "mode": "offline",          # "offline" | "live"
    "interface": "",
    "window_seconds": 300,
    "started_at": None,
    "events": [],               # last 200 scored rows (newest first)
    "tracker": {},              # TunnelIPTracker.get_all() snapshot
    "stats": {"total": 0, "high": 0, "medium": 0, "low": 0, "tunnel": 0},
    "version": 0,
}


def _save(data, name="", thresholds=None, summary=None):
    with _lock:
        _store["version"] += 1
        _store.update(
            data=data,
            pcap_name=name,
            thresholds=thresholds or {},
            summary=summary or {},
        )
        return _store["version"]


def _snapshot():
    with _lock:
        return dict(_store)


def _detector_candidates():
    env_path = os.environ.get("PCAP_DETECTOR_PATH")
    candidates = [
        Path(env_path) if env_path else None,
        Path(__file__).with_name("pcap_detector.py"),
        Path(__file__).parent / "custom-wazuh-model_gguf" / "pcap_detector.py",
        Path.home() / "Desktop" / "SIEM-Minor" / "custom-wazuh-model_gguf" / "pcap_detector.py",
        Path.cwd() / "custom-wazuh-model_gguf" / "pcap_detector.py",
    ]
    unique = []
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


_detector_cache: dict = {}


def _load_detector_module():
    if "module" in _detector_cache:
        return _detector_cache["module"], _detector_cache["path"]
    candidates = _detector_candidates()
    for detector_path in candidates:
        if not detector_path.is_file():
            continue
        spec = importlib.util.spec_from_file_location(
            "linked_pcap_detector", detector_path
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _detector_cache["module"] = module
        _detector_cache["path"] = detector_path
        return module, detector_path
    searched = "\n".join(str(p) for p in candidates)
    raise FileNotFoundError(
        "Could not find pcap_detector.py. "
        "Set PCAP_DETECTOR_PATH or place the detector in one of these paths:\n"
        f"{searched}"
    )


def _json_safe(value):
    if hasattr(value, "item"):
        try:
            value = value.item()
        except Exception:
            pass
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _normalize_rule_reasons(value):
    if not value:
        return []
    if isinstance(value, str):
        return [reason.strip() for reason in value.split(";") if reason.strip()]
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value if item not in (None, "")]
    return [_json_safe(value)]


def _normalize_detector_rows(results):
    rows = []
    for raw_row in results.to_dict(orient="records"):
        row = {key: _json_safe(value) for key, value in raw_row.items()}
        row["rule_reasons"] = _normalize_rule_reasons(row.get("rule_reasons"))
        row["rule_reasons_text"] = "; ".join(row["rule_reasons"])
        rows.append(row)
    return rows


def _build_summary(rows, detector_path):
    return {
        "total_queries": len(rows),
        "tunnels": sum(1 for row in rows if row.get("prediction") == "TUNNEL"),
        "high_risk": sum(1 for row in rows if (row.get("risk_score") or 0) >= 60),
        "unique_sources": len({row.get("src_ip") for row in rows if row.get("src_ip")}),
        "detector_path": str(detector_path),
    }


def _save_uploaded_file(file_storage):
    suffix = Path(file_storage.filename).suffix or DEFAULT_UPLOAD_SUFFIX
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        file_storage.save(tmp.name)
        return tmp.name


def _remove_file(path):
    Path(path).unlink(missing_ok=True)


def _error_response(message, status_code):
    return jsonify({"error": message}), status_code


def _is_loopback_address(value):
    if not value:
        return False
    host = value.split("%", 1)[0]
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def _require_local_access():
    if ALLOW_REMOTE:
        return None
    if request.headers.get("X-Forwarded-For"):
        return _error_response(
            "Dashboard API is restricted to localhost. Set DNS_SHIELD_ALLOW_REMOTE=1 to opt in to remote access.",
            403,
        )
    if _is_loopback_address(request.remote_addr):
        return None
    return _error_response(
        "Dashboard API is restricted to localhost. Set DNS_SHIELD_ALLOW_REMOTE=1 to opt in to remote access.",
        403,
    )


def _normalize_ingested_row(row):
    if not isinstance(row, dict):
        raise ValueError("Each row must be a JSON object")
    normalized = {str(key): _json_safe(value) for key, value in row.items()}
    normalized["rule_reasons"] = _normalize_rule_reasons(normalized.get("rule_reasons"))
    normalized["rule_reasons_text"] = "; ".join(normalized["rule_reasons"])
    return normalized


def _normalize_tracker_snapshot(tracker):
    if not isinstance(tracker, dict):
        raise ValueError("Tracker snapshot must be a JSON object")
    normalized = {}
    for ip, info in list(tracker.items())[:MAX_TRACKER_ITEMS]:
        key = str(ip)
        if isinstance(info, dict):
            normalized[key] = {str(k): _json_safe(v) for k, v in info.items()}
        else:
            normalized[key] = {"value": _json_safe(info)}
    return normalized


def _live_snapshot(since=None):
    with _live_lock:
        events = [dict(event) for event in _live_store["events"]]
        if since is not None and since > 0:
            new_events = [
                dict(event)
                for event in events
                if int(event.get("_event_version", 0)) > since
            ]
            events_payload = None
        else:
            new_events = list(events)
            events_payload = events
        return {
            **_live_store,
            "events": events_payload,
            "new_events": new_events,
            "tracker": dict(_live_store["tracker"]),
            "stats":   dict(_live_store["stats"]),
        }


def _push_live_event(event: dict, tracker: dict, interface: str = "", window_seconds: int = 300):
    """Thread-safe ingestion of a single real-time scored row."""
    with _live_lock:
        next_version = _live_store["version"] + 1
        stored_event = _normalize_ingested_row(event)
        stored_event["_event_version"] = next_version
        _live_store["mode"] = "live"
        if interface:
            _live_store["interface"] = interface
        _live_store["window_seconds"] = window_seconds
        if _live_store["started_at"] is None:
            _live_store["started_at"] = datetime.datetime.now().isoformat()

        # Keep newest N events
        events = _live_store["events"]
        events.insert(0, stored_event)
        if len(events) > MAX_STORED_LIVE_EVENTS:
            events.pop()

        # Merge tracker snapshot
        if tracker:
            _live_store["tracker"].update(tracker)

        # Update rolling stats
        rl = str(stored_event.get("risk_level", "")).lower()
        pred = str(stored_event.get("prediction", ""))
        s = _live_store["stats"]
        s["total"] += 1
        if rl in s:
            s[rl] += 1
        if pred == "TUNNEL":
            s["tunnel"] += 1
        _live_store["version"] = next_version


def _run_detector_pipeline(pcap_path):
    detector, detector_path = _load_detector_module()
    records = detector.parse_pcap(pcap_path)
    features = detector.extract_features(records)
    results = detector.detect(features)
    rows = _normalize_detector_rows(results)

    return {
        "data": rows,
        "pcap_name": Path(pcap_path).name,
        "thresholds": dict(getattr(detector, "THRESHOLDS", {})),
        "summary": _build_summary(rows, detector_path),
    }


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DNSGuard · Threat Analysis</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=Manrope:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f3efe7;--bg1:#faf7f2;--bg2:rgba(255,255,255,.82);--bg3:#e7ecf3;--bg4:#d4dde8;
  --bord:rgba(21,34,53,.08);--bord2:rgba(36,84,215,.16);--bord3:rgba(36,84,215,.28);
  --txt:#162336;--t2:#667385;--t3:#8d97a6;
  --cy:#2454d7;--cy2:rgba(36,84,215,.11);--cy3:rgba(36,84,215,.06);--cy4:rgba(36,84,215,.03);
  --red:#c44b40;--red2:rgba(196,75,64,.14);--red3:rgba(196,75,64,.08);
  --grn:#2e7a54;--grn2:rgba(46,122,84,.12);--grn3:rgba(46,122,84,.07);
  --amb:#c77a18;--amb2:rgba(199,122,24,.14);--amb3:rgba(199,122,24,.08);
  --pur:#7c3aed;--pur2:rgba(124,58,237,.12);--pur3:rgba(124,58,237,.08);
  --bord4:#c8d4e2;
  --syne:'Space Grotesk',sans-serif;--dm:'Manrope',sans-serif;--mono:'IBM Plex Mono',monospace;
  --r4:4px;--r8:10px;--r12:16px;--r16:22px;--r20:26px;--r24:32px;
}
html,body{height:100%;overflow:hidden}
body{font-family:var(--dm);background:radial-gradient(circle at 0% 0%,rgba(36,84,215,.13),transparent 24%),radial-gradient(circle at 92% 10%,rgba(196,75,64,.08),transparent 22%),linear-gradient(180deg,#f7f3ec 0%,#f1ece4 100%);color:var(--txt);display:flex;flex-direction:column;font-size:14px;-webkit-font-smoothing:antialiased;line-height:1.55}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(21,34,53,.024) 1px,transparent 1px),linear-gradient(90deg,rgba(21,34,53,.024) 1px,transparent 1px);background-size:28px 28px;mask-image:linear-gradient(180deg,rgba(0,0,0,.24),transparent 78%);pointer-events:none;z-index:0}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(21,34,53,.16);border-radius:999px}::-webkit-scrollbar-thumb:hover{background:rgba(21,34,53,.26)}

/* HEADER */
header{flex-shrink:0;height:78px;margin:16px 16px 0;padding:0 22px;background:rgba(255,255,255,.76);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border:1px solid var(--bord);border-radius:24px;box-shadow:0 18px 46px rgba(21,34,53,.10);display:flex;align-items:center;gap:16px;position:relative;z-index:200}
.logo{display:flex;align-items:center;gap:12px;text-decoration:none;flex-shrink:0}
.logo-icon{width:42px;height:42px;border-radius:14px;background:linear-gradient(135deg,rgba(36,84,215,.15),rgba(36,84,215,.03)),#fff;border:1px solid rgba(36,84,215,.18);display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden;box-shadow:0 14px 32px rgba(36,84,215,.14)}
.logo-icon::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(36,84,215,.08),transparent);pointer-events:none}
.logo-icon svg{width:20px;height:20px;color:var(--cy);position:relative;z-index:1}
.logo-wordmark{font-family:var(--syne);font-size:16px;font-weight:700;letter-spacing:-.03em;color:var(--txt)}
.logo-wordmark em{color:var(--cy);font-style:normal}
.hd-sep{width:1px;height:22px;background:var(--bord);flex-shrink:0}
#hd-file{font-family:var(--mono);font-size:11px;color:var(--t3);background:rgba(255,255,255,.76);border:1px solid var(--bord);border-radius:999px;padding:8px 14px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;transition:all .25s}
#hd-file.loaded{color:var(--txt);border-color:rgba(36,84,215,.18);background:var(--cy3)}
.hd-r{margin-left:auto;display:flex;align-items:center;gap:10px;flex-wrap:nowrap;overflow:hidden}
.live-pill{display:flex;align-items:center;gap:8px;background:var(--grn3);border:1px solid rgba(46,122,84,.16);border-radius:999px;padding:8px 14px;font-size:11px;font-weight:700;color:var(--grn);font-family:var(--mono);letter-spacing:.04em}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--grn);position:relative;flex-shrink:0}
.live-dot::after{content:'';position:absolute;inset:-4px;border-radius:50%;border:1.5px solid rgba(46,122,84,.35);animation:pulse-ring 2.5s ease infinite;opacity:0}
@keyframes pulse-ring{0%{transform:scale(.5);opacity:.8}100%{transform:scale(1.7);opacity:0}}
#hd-ts{font-size:11px;color:var(--t2);font-family:var(--mono);letter-spacing:.03em}
.hbtn{display:flex;align-items:center;gap:7px;font-size:12px;font-weight:700;padding:10px 15px;border-radius:999px;cursor:pointer;transition:all .16s;border:1px solid var(--bord);background:rgba(255,255,255,.86);color:var(--txt);font-family:var(--dm);white-space:nowrap}
.hbtn:hover{transform:translateY(-1px);border-color:rgba(21,34,53,.18);box-shadow:0 10px 22px rgba(21,34,53,.08)}
.hbtn svg{width:14px;height:14px;flex-shrink:0}
.hbtn.cy{background:linear-gradient(135deg,#1949d8,#5a81f4);border-color:transparent;color:#fff;box-shadow:0 16px 36px rgba(36,84,215,.20)}
.hbtn.cy:hover{box-shadow:0 20px 42px rgba(36,84,215,.24)}

/* NAV */
nav{flex-shrink:0;height:52px;margin:10px 16px 0;background:rgba(255,255,255,.70);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border:1px solid var(--bord);border-radius:18px;padding:6px 8px;display:flex;align-items:center;gap:4px;position:relative;z-index:100;box-shadow:0 14px 36px rgba(21,34,53,.08);overflow-x:auto;overflow-y:hidden;scrollbar-width:none}
nav::-webkit-scrollbar{display:none}
.ntab{display:flex;align-items:center;gap:6px;font-size:11.5px;font-weight:700;color:var(--t2);font-family:var(--dm);padding:0 14px;cursor:pointer;height:100%;border-radius:13px;transition:all .2s;white-space:nowrap;user-select:none;letter-spacing:.01em;flex-shrink:0;position:relative}
.ntab svg{width:13px;height:13px;flex-shrink:0}
.ntab:hover{color:var(--txt);background:rgba(255,255,255,.6)}
.ntab.on{color:var(--cy);background:var(--cy3);box-shadow:0 4px 14px rgba(36,84,215,.10)}
.ntab.on::after{content:'';position:absolute;bottom:4px;left:50%;transform:translateX(-50%);width:18px;height:2px;border-radius:999px;background:var(--cy)}
.nbadge{font-size:9px;font-weight:700;letter-spacing:.04em;background:var(--red2);color:var(--red);border:1px solid rgba(196,75,64,.18);border-radius:999px;padding:1px 5px;display:none;font-family:var(--mono);line-height:1.4;margin-left:2px}
.nbadge.show{display:inline}

/* MAIN */
#page{flex:1;overflow-y:auto;position:relative;z-index:1;padding:16px}
.view{display:none;animation:fadein .3s ease}
.view.on{display:block}
@keyframes fadein{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.view-pad{padding:10px 4px 24px;display:flex;flex-direction:column;gap:24px}

/* UPLOAD */
#view-upload{min-height:calc(100vh - 180px);flex-direction:column;align-items:center;justify-content:center;padding:40px 20px}
#view-upload.on{display:flex}
.upload-wrap{width:100%;max-width:760px;display:flex;flex-direction:column;gap:24px;align-items:center}
.upload-eyebrow{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.2em;text-transform:uppercase;color:var(--cy);opacity:.8}
.drop-zone{width:100%;border-radius:28px;background:rgba(255,255,255,.78);border:1px solid rgba(36,84,215,.16);padding:60px 42px;display:flex;flex-direction:column;align-items:center;gap:20px;cursor:pointer;position:relative;overflow:hidden;transition:border-color .22s,transform .22s,box-shadow .22s,background .22s;box-shadow:0 22px 54px rgba(21,34,53,.08)}
.drop-zone::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at top left,rgba(36,84,215,.12),transparent 36%),linear-gradient(180deg,rgba(255,255,255,.52),transparent);opacity:.9;transition:opacity .3s;pointer-events:none}
.drop-zone:hover,.drop-zone.drag-over{border-color:rgba(36,84,215,.28);transform:translateY(-2px);box-shadow:0 28px 60px rgba(21,34,53,.12);background:rgba(255,255,255,.88)}
.drop-zone::after{content:'';position:absolute;inset:14px;border:1px dashed rgba(36,84,215,.18);border-radius:22px;pointer-events:none}
.dz-icon{width:78px;height:78px;border-radius:24px;background:linear-gradient(135deg,rgba(36,84,215,.12),rgba(36,84,215,.02)),#fff;border:1px solid rgba(36,84,215,.18);display:flex;align-items:center;justify-content:center;position:relative;box-shadow:0 16px 36px rgba(36,84,215,.12)}
.dz-icon::before,.dz-icon::after{display:none}
.dz-icon svg{width:32px;height:32px;color:var(--cy)}
.dz-title{font-family:var(--syne);font-size:34px;font-weight:700;color:var(--txt);letter-spacing:-.04em;text-align:center;max-width:14ch;line-height:1.02}
.dz-title span{color:var(--cy)}
.dz-sub{font-size:15px;color:var(--t2);text-align:center;line-height:1.75;max-width:560px}
.dz-formats{display:flex;gap:8px;flex-wrap:wrap;justify-content:center}
.dz-fmt{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.08em;background:var(--bg2);border:1px solid var(--bord);border-radius:999px;padding:7px 10px;color:var(--t2)}
.dz-btn{display:flex;align-items:center;gap:8px;background:linear-gradient(135deg,#1949d8,#5a81f4);color:#fff;font-family:var(--dm);font-size:13px;font-weight:700;border:none;border-radius:999px;padding:12px 24px;cursor:pointer;transition:all .2s;letter-spacing:.01em;box-shadow:0 16px 34px rgba(36,84,215,.20)}
.dz-btn:hover{transform:translateY(-1px);box-shadow:0 20px 42px rgba(36,84,215,.24)}
.dz-btn svg{width:14px;height:14px}
#file-input{display:none}
.upload-hints{display:flex;gap:24px;flex-wrap:wrap;justify-content:center}
.uhint{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--t2)}
.uhint svg{width:13px;height:13px;color:var(--cy);opacity:.8}

/* SCAN OVERLAY */
#scan-overlay{position:fixed;inset:0;z-index:500;background:rgba(18,28,42,.34);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);display:none;flex-direction:column;align-items:center;justify-content:center;gap:0;padding:40px 20px;opacity:0;transition:opacity .3s}
#scan-overlay.vis{display:flex;opacity:1}
.sc-top{display:flex;flex-direction:column;align-items:center;gap:12px;margin-bottom:28px}
.sc-badge{font-family:var(--mono);font-size:10px;letter-spacing:.18em;font-weight:600;color:var(--cy);text-transform:uppercase;background:rgba(255,255,255,.78);border:1px solid rgba(36,84,215,.16);border-radius:999px;padding:8px 12px}
.sc-filename{font-family:var(--mono);font-size:13px;color:#eef4ff;max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sc-center{width:100%;max-width:480px;display:flex;flex-direction:column;gap:28px;align-items:center;padding:28px;border-radius:28px;background:rgba(255,255,255,.92);border:1px solid rgba(255,255,255,.64);box-shadow:0 28px 74px rgba(18,28,42,.18)}
.sc-ring-wrap{position:relative;width:120px;height:120px}
.sc-ring-svg{width:120px;height:120px;transform:rotate(-90deg)}
.sc-ring-track{fill:none;stroke:#e6ecf4;stroke-width:4}
.sc-ring-fill{fill:none;stroke:var(--cy);stroke-width:4;stroke-linecap:round;stroke-dasharray:339.3;stroke-dashoffset:339.3;transition:stroke-dashoffset .6s cubic-bezier(.4,0,.2,1)}
.sc-pct{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.sc-pct-num{font-family:var(--syne);font-size:26px;font-weight:700;color:var(--txt)}
.sc-pct-lbl{font-family:var(--mono);font-size:9px;color:var(--t3);letter-spacing:.12em;margin-top:-2px}
.sc-bar-wrap{width:100%;display:flex;flex-direction:column;gap:10px}
.sc-bar-track{width:100%;height:6px;background:#e7edf5;border-radius:999px;overflow:hidden}
.sc-bar-fill{height:100%;width:0%;background:linear-gradient(90deg,#2454d7,#6d8df8);border-radius:999px;transition:width .6s cubic-bezier(.4,0,.2,1)}
.sc-msg-wrap{width:100%;display:flex;flex-direction:column;gap:4px}
.sc-msg-current{font-family:var(--syne);font-size:18px;color:var(--txt);letter-spacing:-.03em}
.sc-msg-sub{font-family:var(--dm);font-size:13px;color:var(--t2)}
.sc-stages{width:100%;display:flex;flex-direction:column;gap:0}
.sc-stage{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(21,34,53,.06);font-family:var(--mono);font-size:11px;color:var(--t3);transition:color .3s}
.sc-stage:last-child{border-bottom:none}
.sc-stage.done{color:var(--t2)}.sc-stage.done .ss-dot{background:var(--grn);border-color:var(--grn)}.sc-stage.done .ss-dot::after{display:block}
.sc-stage.active{color:var(--cy)}.sc-stage.active .ss-dot{background:var(--cy);border-color:var(--cy)}
.ss-dot{width:10px;height:10px;border-radius:50%;border:1.5px solid var(--bord4,#d8e0ea);background:var(--bg2);flex-shrink:0;position:relative;transition:all .3s}
.ss-dot::after{content:'✓';display:none;position:absolute;font-size:7px;color:#fff;top:50%;left:50%;transform:translate(-50%,-50%)}
.ss-lbl{flex:1}.ss-time{font-size:9px;color:var(--t3);letter-spacing:.04em}
/* Score track uses neutral grey that works in both modes */
.score-track{height:6px;border-radius:999px;background:var(--bg3);overflow:hidden;margin-top:4px}
.score-fill{height:100%;width:0%;border-radius:999px;transition:width .8s cubic-bezier(.4,0,.2,1) .3s}
/* Table details button — no hover lift */
.hbtn-sm{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:700;padding:5px 10px;border-radius:999px;cursor:pointer;transition:background .15s,color .15s;border:1px solid var(--bord);background:var(--bg2);color:var(--t2);font-family:var(--dm);white-space:nowrap}
.hbtn-sm:hover{background:var(--cy2);color:var(--cy);border-color:var(--bord2)}
.hbtn-sm svg{width:11px;height:11px;flex-shrink:0}

/* VIEW HEADER */
.vh{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;flex-wrap:wrap}
.vh-eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--cy);opacity:.8;margin-bottom:6px}
.vh-title{font-family:var(--syne);font-size:28px;font-weight:700;color:var(--txt);letter-spacing:-.04em;line-height:1}
.vh-sub{font-size:14px;color:var(--t2);margin-top:8px;line-height:1.7;max-width:58ch}
.vh-right{display:flex;gap:8px;align-items:center}

/* KPI GRID */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
@media(max-width:900px){.kpi-grid{grid-template-columns:repeat(2,1fr)}}
.kpi-card{background:var(--bg2);border:1px solid var(--bord);border-radius:24px;padding:24px;position:relative;overflow:hidden;transition:border-color .2s,transform .15s,box-shadow .2s;animation:card-in .4s ease both;box-shadow:0 18px 40px rgba(21,34,53,.08)}
.kpi-card:nth-child(1){animation-delay:.05s}.kpi-card:nth-child(2){animation-delay:.1s}.kpi-card:nth-child(3){animation-delay:.15s}.kpi-card:nth-child(4){animation-delay:.2s}
@keyframes card-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.kpi-card:hover{border-color:rgba(21,34,53,.16);transform:translateY(-2px);box-shadow:0 24px 48px rgba(21,34,53,.10)}
.kpi-card::before{content:'';position:absolute;top:0;left:24px;right:24px;height:1px;background:linear-gradient(90deg,transparent,rgba(36,84,215,.18),transparent)}
.kpi-card.red::before{background:linear-gradient(90deg,transparent,rgba(196,75,64,.24),transparent)}
.kpi-card.amb::before{background:linear-gradient(90deg,transparent,rgba(199,122,24,.24),transparent)}
.kpi-card.grn::before{background:linear-gradient(90deg,transparent,rgba(46,122,84,.24),transparent)}
/* Compact stat cards in live/tunnel views — override hover lift + shimmer */
#live-stats-row .kpi-card,#tunnel-summary-cards .kpi-card{animation:none;overflow:visible}
#live-stats-row .kpi-card:hover,#tunnel-summary-cards .kpi-card:hover{transform:none}
#live-stats-row .kpi-card::before,#tunnel-summary-cards .kpi-card::before{display:none}
.kpi-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.kpi-icon{width:42px;height:42px;border-radius:14px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.kpi-icon svg{width:18px;height:18px}
.kpi-delta{font-family:var(--mono);font-size:10px;font-weight:700;padding:4px 8px;border-radius:999px}
.kpi-delta.up{color:var(--red);background:var(--red2)}.kpi-delta.ok{color:var(--grn);background:var(--grn2)}.kpi-delta.neu{color:var(--t2);background:#edf2f7}
.kpi-num{font-family:var(--syne);font-size:40px;font-weight:800;letter-spacing:-.05em;line-height:1;margin-bottom:8px}
.kpi-label{font-size:12px;color:var(--t2);font-weight:700;letter-spacing:.02em}
.kpi-sub{font-family:var(--mono);font-size:11px;color:var(--t3);margin-top:6px}
.kpi-card.cy .kpi-icon{background:var(--cy2);color:var(--cy)}.kpi-card.cy .kpi-num{color:var(--cy)}
.kpi-card.red .kpi-icon{background:var(--red2);color:var(--red)}.kpi-card.red .kpi-num{color:var(--red)}
.kpi-card.amb .kpi-icon{background:var(--amb2);color:var(--amb)}.kpi-card.amb .kpi-num{color:var(--amb)}
.kpi-card.grn .kpi-icon{background:var(--grn2);color:var(--grn)}.kpi-card.grn .kpi-num{color:var(--grn)}

/* OVERVIEW GRID */
.ov-grid{display:grid;grid-template-columns:1.35fr .95fr;gap:16px}
@media(max-width:1100px){.ov-grid{grid-template-columns:1fr}}
.ov-card{background:var(--bg2);border:1px solid var(--bord);border-radius:24px;padding:24px;box-shadow:0 18px 40px rgba(21,34,53,.08);display:flex;flex-direction:column;gap:18px;min-height:100%}
.ov-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
.ov-card-title{font-family:var(--syne);font-size:18px;font-weight:700;color:var(--txt);letter-spacing:-.03em}
.ov-card-sub{font-size:13px;color:var(--t2);line-height:1.7;max-width:58ch}
.assess-chip{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:999px;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--bord);background:var(--bg2);color:var(--t2)}
.assess-chip.critical{background:var(--red2);border-color:rgba(196,75,64,.22);color:var(--red)}
.assess-chip.warn{background:var(--amb2);border-color:rgba(199,122,24,.22);color:var(--amb)}
.assess-chip.ok{background:var(--grn3);border-color:rgba(46,122,84,.18);color:var(--grn)}
.assess-chip svg{width:12px;height:12px}
.assess-body{font-size:24px;line-height:1.2;font-weight:800;letter-spacing:-.04em;color:var(--txt);max-width:24ch}
.assess-meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
@media(max-width:720px){.assess-meta{grid-template-columns:repeat(2,minmax(0,1fr))}}
.assess-stat{background:var(--bg2);border:1px solid var(--bord);border-radius:18px;padding:14px 16px;display:flex;flex-direction:column;gap:4px}
.assess-stat-label{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--t3)}
.assess-stat-value{font-family:var(--syne);font-size:22px;font-weight:700;letter-spacing:-.04em;color:var(--txt)}
.assess-points{display:grid;gap:10px}
.assess-point{display:flex;gap:10px;align-items:flex-start;padding:11px 12px;border-radius:16px;background:rgba(36,84,215,.04);border:1px solid rgba(36,84,215,.08);color:var(--t2)}
.assess-point svg{width:15px;height:15px;color:var(--cy);flex-shrink:0;margin-top:2px}
.assess-actions{display:flex;gap:10px;flex-wrap:wrap}
.mini-grid{display:grid;grid-template-columns:1fr;gap:14px}
.mini-list{display:grid;gap:10px}
.mini-item{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:14px 15px;border-radius:18px;border:1px solid var(--bord);background:var(--bg2)}
.mini-main{min-width:0;display:flex;flex-direction:column;gap:5px}
.mini-kicker{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--t3)}
.mini-title{font-size:13px;font-weight:700;color:var(--txt);line-height:1.5;word-break:break-word}
.mini-sub{font-size:12px;color:var(--t2);line-height:1.6}
.mini-side{display:flex;flex-direction:column;align-items:flex-end;gap:8px;flex-shrink:0}
.mini-score{min-width:48px;text-align:center;padding:8px 10px;border-radius:14px;font-family:var(--syne);font-size:20px;font-weight:700;letter-spacing:-.04em;background:rgba(36,84,215,.08);color:var(--cy)}
.mini-score.warn{background:var(--amb2);color:var(--amb)}.mini-score.bad{background:var(--red2);color:var(--red)}
.mini-empty{padding:22px 18px;border:1px dashed rgba(21,34,53,.12);border-radius:18px;text-align:center;font-size:13px;color:var(--t3);background:var(--bg2)}

/* CHART GRID */
.chart-row{display:grid;gap:16px}
.chart-row.r2{grid-template-columns:2fr 1fr}.chart-row.r3{grid-template-columns:1fr 1fr 1fr}
@media(max-width:800px){.chart-row.r2,.chart-row.r3{grid-template-columns:1fr}}
.chart-card{background:var(--bg2);border:1px solid var(--bord);border-radius:24px;padding:24px;display:flex;flex-direction:column;gap:16px;animation:card-in .4s ease .25s both;box-shadow:0 18px 40px rgba(21,34,53,.08)}
.cc-head{display:flex;align-items:center;justify-content:space-between;gap:8px}
.cc-title{font-family:var(--syne);font-size:15px;font-weight:700;color:var(--txt);letter-spacing:-.03em}
.cc-sub{font-size:11px;color:var(--t3);font-family:var(--mono)}
.cc-badge{font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.08em;background:var(--cy3);color:var(--cy);border:1px solid var(--bord2);border-radius:999px;padding:5px 8px;text-transform:uppercase}
.chart-wrap{position:relative;width:100%}
.chart-wrap.tall{height:220px}.chart-wrap.short{height:170px}.chart-wrap.donut{height:220px;display:flex;align-items:center;justify-content:center}

/* ALERTS TABLE */
.tbl-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:var(--bg2);border:1px solid var(--bord);border-radius:24px;padding:14px 18px;box-shadow:0 18px 40px rgba(21,34,53,.08)}
.srch-wrap{position:relative;flex:1;min-width:180px}
.srch-wrap svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);width:15px;height:15px;color:var(--t2);pointer-events:none}
#qsrch{width:100%;background:var(--bg1);border:1px solid var(--bord);border-radius:18px;padding:12px 14px 12px 42px;font-size:13px;color:var(--txt);font-family:var(--dm);transition:border-color .2s;outline:none}
#qsrch::placeholder{color:var(--t3)}
#qsrch:focus{border-color:var(--bord3);box-shadow:0 0 0 4px rgba(36,84,215,.08)}
.filt-btn{display:flex;align-items:center;gap:5px;font-size:11px;font-weight:700;padding:10px 12px;border-radius:999px;cursor:pointer;border:1px solid var(--bord);background:var(--bg2);color:var(--t2);font-family:var(--dm);transition:all .15s;white-space:nowrap}
.filt-btn:hover{border-color:rgba(21,34,53,.16);color:var(--txt)}.filt-btn.on{background:var(--cy2);border-color:rgba(36,84,215,.18);color:var(--txt)}
.filt-btn svg{width:11px;height:11px}
.tbl-info{font-family:var(--mono);font-size:10px;color:var(--t3);margin-left:auto}
.tbl-wrap{background:rgba(255,255,255,.82);border:1px solid var(--bord);border-radius:24px;overflow:hidden;box-shadow:0 18px 40px rgba(21,34,53,.08)}
.atbl{width:100%;border-collapse:collapse}
.atbl thead{background:var(--bg2)}
.atbl th{padding:14px 16px;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--t3);text-align:left;font-family:var(--mono);border-bottom:1px solid var(--bord);white-space:nowrap;cursor:pointer;user-select:none;transition:color .15s}
.atbl th:hover{color:var(--t2)}.atbl th svg{display:inline;width:10px;height:10px;margin-left:3px}
.atbl tbody tr{border-bottom:1px solid var(--bord);cursor:pointer;transition:background .12s}
.atbl tbody tr:last-child{border-bottom:none}.atbl tbody tr:hover{background:rgba(36,84,215,.045)}
.atbl td{padding:14px 16px;font-size:12px;vertical-align:middle}
.td-query{font-family:var(--mono);font-size:11px;color:var(--txt);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.td-sub{font-family:var(--mono);font-size:11px;color:var(--cy);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.td-ip{font-family:var(--mono);font-size:11px;color:var(--t2)}
.td-type{font-family:var(--mono);font-size:10px;font-weight:500;background:var(--bg2);border:1px solid var(--bord);border-radius:999px;padding:5px 8px;color:var(--t2);display:inline-block}
.td-type.special{background:var(--amb2);border-color:rgba(199,122,24,.18);color:var(--amb)}
.risk-badge{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.04em;border-radius:999px;padding:6px 10px;white-space:nowrap}
.risk-badge.hi{background:var(--red2);color:var(--red);border:1px solid rgba(196,75,64,.18)}
.risk-badge.med{background:var(--amb2);color:var(--amb);border:1px solid rgba(199,122,24,.18)}
.risk-badge.lo{background:var(--grn2);color:var(--grn);border:1px solid rgba(46,122,84,.18)}
.risk-badge::before{content:'';width:5px;height:5px;border-radius:50%;background:currentColor;display:inline-block}
.score-bar-mini{height:6px;border-radius:999px;background:#e9edf3;width:80px;overflow:hidden;display:inline-block;vertical-align:middle}
.score-bar-mini-fill{height:100%;border-radius:999px;transition:width .3s}
.tbl-empty{padding:60px 20px;text-align:center;font-size:13px;color:var(--t3);display:flex;flex-direction:column;align-items:center;gap:8px}
.tbl-empty svg{width:28px;height:28px;color:var(--t3);opacity:.4}

/* HOSTS VIEW */
.host-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
.host-card{background:var(--bg2);border:1px solid var(--bord);border-radius:24px;padding:22px;display:flex;flex-direction:column;gap:14px;transition:border-color .2s,transform .15s,box-shadow .2s;box-shadow:0 18px 40px rgba(21,34,53,.08)}
.host-card:hover{border-color:rgba(21,34,53,.16);transform:translateY(-2px);box-shadow:0 22px 48px rgba(21,34,53,.10)}
.hc-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.hc-ip{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--txt)}
.hc-count{font-family:var(--mono);font-size:10px;color:var(--t2)}
.hc-bar-row{display:flex;flex-direction:column;gap:6px}
.hc-bar-label{display:flex;justify-content:space-between;font-size:11px}
.hc-bar-label span:first-child{color:var(--t3);font-family:var(--mono)}
.hc-bar-label span:last-child{color:var(--t2);font-family:var(--mono)}
.hc-bar{height:6px;border-radius:999px;background:#e9edf3;overflow:hidden}
.hc-bar-fill{height:100%;border-radius:999px}
.hc-stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0;border:1px solid var(--bord);border-radius:18px;overflow:hidden;background:var(--bg2)}
.hc-stat{padding:10px;text-align:center;border-right:1px solid var(--bord)}
.hc-stat:last-child{border-right:none}
.hc-stat-num{font-family:var(--syne);font-size:18px;font-weight:700}
.hc-stat-lbl{font-size:9px;color:var(--t3);font-family:var(--mono);letter-spacing:.08em;margin-top:3px}
.hc-feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:4px}
.hc-feat{background:rgba(36,84,215,.04);border:1px solid rgba(36,84,215,.08);border-radius:14px;padding:10px 12px;display:flex;flex-direction:column;gap:3px}
.hc-feat.warn{background:var(--amb2);border-color:rgba(199,122,24,.20)}
.hc-feat.danger{background:var(--red2);border-color:rgba(196,75,64,.20)}
.hc-feat-num{font-family:var(--syne);font-size:16px;font-weight:700;color:var(--txt)}
.hc-feat-lbl{font-size:9px;color:var(--t3);font-family:var(--mono);letter-spacing:.06em;line-height:1.3}
.hc-divider{height:1px;background:var(--bord);margin:2px 0}

/* FEATURES VIEW */
.feat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
@media(max-width:900px){.feat-row{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.feat-row{grid-template-columns:1fr}}
.feat-stat-card{background:var(--bg2);border:1px solid var(--bord);border-radius:20px;padding:20px;box-shadow:0 12px 30px rgba(21,34,53,.07);display:flex;flex-direction:column;gap:10px}
.feat-stat-head{display:flex;align-items:center;justify-content:space-between}
.feat-stat-label{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--t3)}
.feat-stat-icon{width:32px;height:32px;border-radius:10px;display:flex;align-items:center;justify-content:center}
.feat-stat-icon svg{width:14px;height:14px}
.feat-stat-val{font-family:var(--syne);font-size:28px;font-weight:700;letter-spacing:-.04em;color:var(--txt)}
.feat-stat-sub{font-size:11px;color:var(--t2);font-family:var(--mono)}
.feat-thresh-bar{height:8px;border-radius:999px;background:#e9edf3;overflow:hidden;position:relative}
.feat-thresh-fill{height:100%;border-radius:999px;transition:width .6s cubic-bezier(.4,0,.2,1)}
.feat-thresh-marker{position:absolute;top:-2px;bottom:-2px;width:2px;border-radius:2px;background:var(--t3);opacity:.5}

/* THRESHOLD TABLE */
.thresh-summary{background:var(--bg2);border:1px solid var(--bord);border-radius:24px;overflow:hidden;box-shadow:0 18px 40px rgba(21,34,53,.08)}
.thresh-summary-head{padding:20px 24px;border-bottom:1px solid var(--bord);display:flex;align-items:center;justify-content:space-between}
.thresh-summary-title{font-family:var(--syne);font-size:16px;font-weight:700;color:var(--txt);letter-spacing:-.02em}
.thresh-tbl{width:100%;border-collapse:collapse}
.thresh-tbl th{padding:12px 20px;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--t3);text-align:left;font-family:var(--mono);border-bottom:1px solid var(--bord);background:var(--bg2)}
.thresh-tbl td{padding:14px 20px;font-size:12px;border-bottom:1px solid var(--bord)}
.thresh-tbl tr:last-child td{border-bottom:none}
.thresh-tbl tr:hover td{background:rgba(36,84,215,.03)}
.feat-name{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--txt)}
.feat-desc{font-size:11px;color:var(--t2);margin-top:2px}
.feat-thr{font-family:var(--mono);font-size:11px;color:var(--cy)}
.feat-hit-badge{display:inline-flex;align-items:center;gap:4px;font-family:var(--mono);font-size:10px;font-weight:700;border-radius:999px;padding:4px 8px}
.feat-hit-badge.has{background:var(--red2);color:var(--red)}
.feat-hit-badge.none{background:var(--grn2);color:var(--grn)}
.feat-pct{font-family:var(--mono);font-size:11px;color:var(--t2)}

/* SETTINGS VIEW */
.settings-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:700px){.settings-grid{grid-template-columns:1fr}}
.set-card{background:var(--bg2);border:1px solid var(--bord);border-radius:24px;padding:24px;display:flex;flex-direction:column;gap:16px;box-shadow:0 18px 40px rgba(21,34,53,.08)}
.set-card.full{grid-column:1/-1}
.set-card-title{font-family:var(--syne);font-size:15px;font-weight:700;color:var(--txt);display:flex;align-items:center;gap:8px;letter-spacing:-.02em}
.set-card-title svg{width:15px;height:15px;color:var(--cy)}
.thr-row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--bord);font-size:12px}
.thr-row:last-child{border-bottom:none}
.thr-key{display:flex;align-items:center;gap:8px;flex:1;color:var(--t2);font-family:var(--mono);font-size:11px}
.thr-key svg{width:12px;height:12px;color:var(--cy);opacity:.6}
.thr-hint{font-size:10px;color:var(--t3);margin-left:auto}
.thr-val{font-family:var(--mono);font-size:11px;font-weight:600;background:var(--cy3);border:1px solid var(--bord2);border-radius:999px;padding:6px 10px;color:var(--cy)}
.mth-item{display:flex;gap:14px;align-items:flex-start;padding:12px 0;border-bottom:1px solid var(--bord)}
.mth-item:last-child{border-bottom:none}
.mth-dot{width:36px;height:36px;border-radius:14px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.mth-dot svg{width:14px;height:14px}
.mth-key{font-size:13px;font-weight:700;color:var(--txt);margin-bottom:4px}
.mth-val{font-size:12px;color:var(--t2);line-height:1.65}
.score-formula{background:var(--bg2);border:1px solid var(--bord2);border-radius:18px;padding:14px 16px;font-family:var(--mono);font-size:12px;color:var(--cy);display:flex;gap:12px;align-items:center}
.sf-part{display:flex;flex-direction:column;gap:2px}
.sf-part span:first-child{font-size:18px;font-weight:700;font-family:var(--syne)}
.sf-part span:last-child{font-size:9px;color:var(--t3);letter-spacing:.08em}
.sf-op{font-size:16px;color:var(--t3)}

/* DRAWER */
#drawer-overlay{position:fixed;inset:0;z-index:800;background:rgba(18,28,42,.32);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);display:none;opacity:0;transition:opacity .25s}
#drawer-overlay.vis{opacity:1}
#drawer{position:absolute;top:0;right:0;bottom:0;width:500px;max-width:100vw;background:rgba(249,247,242,.98);border-left:1px solid var(--bord);display:flex;flex-direction:column;transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);overflow:hidden;box-shadow:-18px 0 40px rgba(21,34,53,.10)}
#drawer.open{transform:translateX(0)}
.drw-hdr{padding:22px 22px 18px;border-bottom:1px solid var(--bord);display:flex;align-items:flex-start;gap:12px;flex-shrink:0}
.drw-icon{width:48px;height:48px;border-radius:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.drw-hdr-info{flex:1;min-width:0}
.drw-query-text{font-family:var(--mono);font-size:12px;color:var(--txt);word-break:break-all;line-height:1.6}
.drw-query-sub{font-size:11px;color:var(--t3);margin-top:4px;font-family:var(--mono)}
.drw-close{width:34px;height:34px;border-radius:999px;border:1px solid var(--bord);background:var(--bg2);display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;color:var(--t2);transition:all .15s}
.drw-close:hover{background:var(--cy3);color:var(--txt)}
.drw-close svg{width:13px;height:13px}
#drw-body{flex:1;overflow-y:auto;padding:0 22px 28px}
.score-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:20px 0;border-bottom:1px solid var(--bord)}
.score-box{display:flex;flex-direction:column;gap:8px}
.score-num{font-family:var(--syne);font-size:46px;font-weight:800;line-height:1;letter-spacing:-.05em}
.score-lbl{font-family:var(--mono);font-size:10px;color:var(--t2);letter-spacing:.05em}
.score-track{height:6px;border-radius:999px;background:#e7edf5;overflow:hidden;margin-top:4px}
.score-fill{height:100%;width:0%;border-radius:999px;transition:width .8s cubic-bezier(.4,0,.2,1) .3s}
.score-ticks{display:flex;justify-content:space-between;font-size:9px;color:var(--t3);font-family:var(--mono);margin-top:2px}
.verdict-box{display:flex;flex-direction:column;justify-content:center;gap:6px}
.verdict-tag{font-family:var(--syne);font-size:16px;font-weight:700;letter-spacing:-.02em}
.verdict-sub{font-size:12px;color:var(--t2);line-height:1.7}
.drw-section{padding:16px 0;border-bottom:1px solid var(--bord)}
.drw-section:last-child{border-bottom:none}
.drw-sec-title{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:9px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--t3);margin-bottom:10px}
.drw-sec-title svg{width:11px;height:11px;color:var(--cy);opacity:.7}
.kv-list{display:flex;flex-direction:column;gap:0}
.kv{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px dashed var(--bord);gap:8px}
.kv:last-child{border-bottom:none}
.kv-k{font-size:12px;color:var(--t2);flex:1}
.kv-v{font-family:var(--mono);font-size:11px;color:var(--txt);text-align:right;word-break:break-all;max-width:60%}
.kv-v.r{color:var(--red)}.kv-v.a{color:var(--amb)}.kv-v.g{color:var(--grn)}.kv-v.b{color:var(--cy)}
.kv-2col{display:grid;grid-template-columns:1fr 1fr;gap:0}
.kv-2col .kv{padding:7px 10px;border:none;border-bottom:1px dashed var(--bord);background:rgba(36,84,215,.025);border-radius:0}
.kv-2col .kv:nth-child(odd){border-right:1px dashed var(--bord)}
.rule-item{display:flex;gap:10px;align-items:flex-start;padding:7px 0}
.rule-dot{width:22px;height:22px;border-radius:8px;background:var(--amb2);color:var(--amb);display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
.rule-dot svg{width:10px;height:10px}
.rule-item span{font-size:12px;color:var(--t2);line-height:1.65}
.no-rules{font-size:12px;color:var(--t3);font-style:italic;padding:6px 0}
.subdomain-pill{display:inline-block;font-family:var(--mono);font-size:11px;background:var(--cy2);border:1px solid var(--bord2);border-radius:10px;padding:6px 10px;color:var(--cy);word-break:break-all;line-height:1.5;margin-top:4px;max-width:100%}
.mini-score-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px}
.mscore-box{background:var(--bg2);border:1px solid var(--bord);border-radius:14px;padding:12px 14px;display:flex;flex-direction:column;gap:3px}
.mscore-val{font-family:var(--syne);font-size:20px;font-weight:700;color:var(--txt)}
.mscore-lbl{font-size:10px;color:var(--t3);font-family:var(--mono);letter-spacing:.06em}

/* TOAST */
#toasts{position:fixed;bottom:20px;right:20px;z-index:1000;display:flex;flex-direction:column;gap:10px;align-items:flex-end}
.toast{display:flex;align-items:center;gap:8px;background:var(--bg1);border:1px solid var(--bord);border-radius:18px;padding:12px 14px;font-size:12px;color:var(--txt);box-shadow:0 16px 34px rgba(21,34,53,.12);animation:toastin .2s ease;font-family:var(--dm)}
@keyframes toastin{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:translateX(0)}}
.toast.warn{border-color:rgba(199,122,24,.18)}
.t-icon{width:20px;height:20px;border-radius:999px;display:flex;align-items:center;justify-content:center;background:var(--grn2);color:var(--grn);flex-shrink:0}
.t-icon.warn{background:var(--amb2);color:var(--amb)}
.t-icon svg{width:11px;height:11px}

/* EMPTY PANEL */
.panel-empty{padding:48px 20px;text-align:center;display:flex;flex-direction:column;align-items:center;gap:10px}
.panel-empty svg{width:38px;height:38px;color:var(--t3);opacity:.4}
.panel-empty h3{font-family:var(--syne);font-size:18px;font-weight:700;color:var(--t2);letter-spacing:-.02em}
.panel-empty p{font-size:13px;color:var(--t3);max-width:280px;line-height:1.7}

/* LEGEND */
.legend{display:flex;flex-wrap:wrap;gap:10px}
.leg-item{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--t2)}
.leg-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}

/* DARK MODE TOGGLE — extends .hbtn, only adds user-select */
.dark-toggle{display:flex;align-items:center;gap:7px;font-size:12px;font-weight:700;padding:10px 15px;border-radius:999px;cursor:pointer;transition:all .16s;border:1px solid var(--bord);background:rgba(255,255,255,.86);color:var(--txt);font-family:var(--dm);white-space:nowrap;user-select:none}
.dark-toggle:hover{transform:translateY(-1px);border-color:rgba(21,34,53,.18);box-shadow:0 10px 22px rgba(21,34,53,.08)}
.dark-toggle svg{width:14px;height:14px;flex-shrink:0}
body.dark{color-scheme:dark;--bg:#0e1420;--bg1:#131926;--bg2:rgba(19,25,38,.92);--bg3:#1a2135;--bg4:#222d44;--bord:rgba(255,255,255,.08);--bord2:rgba(99,149,255,.22);--bord3:rgba(99,149,255,.35);--bord4:rgba(255,255,255,.14);--txt:#e8edf5;--t2:#8d9ab0;--t3:#5a6680;--cy:#6395ff;--cy2:rgba(99,149,255,.14);--cy3:rgba(99,149,255,.08);--cy4:rgba(99,149,255,.04);--red:#f07068;--red2:rgba(240,112,104,.18);--red3:rgba(240,112,104,.10);--grn:#4ead7a;--grn2:rgba(78,173,122,.16);--grn3:rgba(78,173,122,.09);--amb:#e8952a;--amb2:rgba(232,149,42,.18);--amb3:rgba(232,149,42,.10);--pur:#a97bf5;--pur2:rgba(169,123,245,.16);--pur3:rgba(169,123,245,.10);background:radial-gradient(circle at 0% 0%,rgba(99,149,255,.09),transparent 24%),radial-gradient(circle at 92% 10%,rgba(240,112,104,.06),transparent 22%),linear-gradient(180deg,#0e1420 0%,#0b111c 100%)}
body.dark header,body.dark nav{background:rgba(19,25,38,.82)}
body.dark .ov-card,body.dark .chart-card,body.dark .kpi-card,body.dark .tbl-wrap,body.dark .sc-center,body.dark .drop-zone{background:rgba(19,25,38,.92);border-color:var(--bord)}
body.dark .ntab.on{background:rgba(255,255,255,.06)}
body.dark .hbtn,body.dark .dark-toggle{background:rgba(255,255,255,.06);color:var(--txt);border-color:var(--bord)}
body.dark .hbtn.cy{background:linear-gradient(135deg,#1949d8,#5a81f4)}
body.dark .atbl thead tr{background:rgba(255,255,255,.04)}
body.dark .atbl tbody tr:hover{background:rgba(99,149,255,.06)}
body.dark #drawer{background:var(--bg1)}
body.dark .mscore-box,body.dark .kv{background:rgba(255,255,255,.03)}
body.dark input[type=text]{background:rgba(255,255,255,.06);color:var(--txt);border-color:var(--bord)}
body.dark .set-card{border-color:var(--bord)}
body.dark .filt-btn{color:var(--t2);border-color:var(--bord)}
body.dark .filt-btn.on{background:var(--cy2);color:var(--txt)}
body.dark #view-live pre{background:var(--bg3) !important;border-color:var(--bord) !important;color:var(--txt) !important}
body.dark nav::-webkit-scrollbar{display:none}
body.dark .toast{background:var(--bg1);border-color:var(--bord);color:var(--txt);box-shadow:0 16px 34px rgba(0,0,0,.4)}
body.dark .tbl-toolbar{background:var(--bg2);border-color:var(--bord)}
body.dark .feat-stat-card{border-color:var(--bord)}
body.dark .thresh-summary{border-color:var(--bord)}
body.dark .thresh-tbl th{background:rgba(255,255,255,.04)}
body.dark .thresh-tbl tr:hover td{background:rgba(99,149,255,.05)}
body.dark .assess-stat{border-color:var(--bord)}
body.dark .mini-item{border-color:var(--bord)}
body.dark .host-card{border-color:var(--bord)}
body.dark .mini-empty{background:rgba(255,255,255,.03);border-color:var(--bord);color:var(--t3)}

/* kpi-card compact variant — shared by Live Feed stats row and Tunnel summary cards */
#live-stats-row .kpi-card,#tunnel-summary-cards .kpi-card{display:flex;align-items:center;gap:14px;padding:18px 20px;animation:none}
#live-stats-row .kpi-body,#tunnel-summary-cards .kpi-body{display:flex;flex-direction:column;gap:3px;min-width:0}
#live-stats-row .kpi-val,#tunnel-summary-cards .kpi-val{font-family:var(--syne);font-size:26px;font-weight:800;letter-spacing:-.04em;line-height:1;color:var(--txt)}
#live-stats-row .kpi-label,#tunnel-summary-cards .kpi-label{font-size:11px;font-weight:700;color:var(--t2);letter-spacing:.01em}
#live-stats-row .kpi-sub,#tunnel-summary-cards .kpi-sub{font-family:var(--mono);font-size:10px;color:var(--t3);margin-top:1px}
#live-stats-row .kpi-icon,#tunnel-summary-cards .kpi-icon{flex-shrink:0;width:42px;height:42px;border-radius:14px;display:flex;align-items:center;justify-content:center}
#live-stats-row .kpi-icon svg,#tunnel-summary-cards .kpi-icon svg{width:18px;height:18px}

/* Live Feed event card */
.live-event-card{background:var(--bg2);border:1px solid var(--bord);border-radius:var(--r8);padding:14px 16px;display:flex;align-items:flex-start;gap:14px;animation:fadein .3s ease;cursor:pointer;transition:box-shadow .15s,border-color .15s}
.live-event-card:hover{box-shadow:0 6px 18px rgba(21,34,53,.08)}
body.dark .live-event-card{background:rgba(19,25,38,.92)}
/* Score badge used inside live event cards */
.live-score-badge{width:44px;height:44px;display:flex;align-items:center;justify-content:center;border-radius:12px;font-family:var(--syne);font-size:16px;font-weight:800;letter-spacing:-.04em;background:rgba(36,84,215,.08);color:var(--cy)}
.live-score-badge.warn{background:var(--amb2);color:var(--amb)}
.live-score-badge.bad{background:var(--red2);color:var(--red)}
#live-stats-row{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
#tunnel-summary-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
@media(max-width:1000px){#live-stats-row{grid-template-columns:repeat(3,1fr)}}
@media(max-width:640px){#live-stats-row,#tunnel-summary-cards{grid-template-columns:1fr 1fr}}
body.dark #view-live .kpi-card,
body.dark #view-tunnels .kpi-card{border-color:var(--bord)}
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <a class="logo" href="#">
    <div class="logo-icon">
      <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <span class="logo-wordmark">DNS <em>Shield</em></span>
  </a>
  <div class="hd-sep"></div>
  <div id="hd-file">no file loaded</div>
  <div class="hd-r">
    <div class="live-pill" id="hd-live-pill" style="display:none"><div class="live-dot"></div>LIVE CAPTURE</div>
    <div class="live-pill" id="hd-ready-pill"><div class="live-dot"></div>SYSTEM READY</div>
    <div id="hd-ts">--:--:--</div>
    <div class="hd-sep"></div>
    <button class="hbtn" id="btn-new-scan" onclick="resetToUpload()">
      <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
      New Scan
    </button>
    <button class="dark-toggle" id="btn-dark" onclick="toggleDark()" title="Toggle dark mode">
      <svg id="dark-icon" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
    </button>
    <button class="hbtn cy" id="btn-export" onclick="exportCSV()">
      <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export
    </button>
  </div>
</header>

<!-- NAV -->
<nav>
  <div class="ntab" data-p="overview">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
    Overview
  </div>
  <div class="ntab" data-p="alerts">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    Alerts
    <span class="nbadge" id="badge-alerts"></span>
  </div>
  <div class="ntab" data-p="features">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
    Feature Analysis
  </div>
  <div class="ntab" data-p="hosts">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
    Hosts
  </div>
  <div class="ntab" data-p="live">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M10 15l5-3-5-3z"/></svg>
    Live Feed<span class="nbadge" id="nb-live"></span>
  </div>
  <div class="ntab" data-p="tunnels">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    Confirmed Tunnels<span class="nbadge" id="nb-tunnels"></span>
  </div>
  <div class="ntab" data-p="settings">
    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
    Settings
  </div>
</nav>

<!-- PAGE -->
<div id="page">

  <!-- UPLOAD -->
  <div id="view-upload" class="view on">
    <div class="upload-wrap">
      <div class="upload-eyebrow">DNS Tunneling Detection System · v6.0</div>
      <div class="drop-zone" id="drop-zone">
        <div class="dz-icon">
          <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div class="dz-title">Drop your <span>PCAP file</span> here</div>
        <div class="dz-sub">Upload a packet capture to run deep DNS tunnel analysis using heuristic rules and Isolation Forest ML — all 27 detector features displayed clearly.</div>
        <div class="dz-formats">
          <span class="dz-fmt">.PCAP</span><span class="dz-fmt">.PCAPNG</span><span class="dz-fmt">.CAP</span><span class="dz-fmt">up to 200 MB</span>
        </div>
        <button class="dz-btn" onclick="document.getElementById('file-input').click()">
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          Choose File to Analyse
        </button>
      </div>
      <div class="upload-hints">
        <div class="uhint"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>All 27 detector features shown</div>
        <div class="uhint"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Real-time analysis, avg. 8s</div>
        <div class="uhint"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Rule engine + Isolation Forest</div>
      </div>
    </div>
    <input type="file" id="file-input" accept=".pcap,.pcapng,.cap"/>
  </div>

  <!-- OVERVIEW -->
  <div id="view-overview" class="view">
    <div class="view-pad">
      <div class="vh">
        <div class="vh-left">
          <div class="vh-eyebrow">Threat Intelligence Report</div>
          <div class="vh-title">Network Overview</div>
          <div class="vh-sub" id="ov-sub">Summary of DNS traffic analysis</div>
        </div>
        <div class="vh-right">
          <div class="filt-btn" id="ov-mode-btn" onclick="toggleOvMode()">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
            Tunnels Only
          </div>
        </div>
      </div>
      <div class="kpi-grid">
        <div class="kpi-card cy">
          <div class="kpi-top">
            <div class="kpi-icon"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg></div>
            <div class="kpi-delta neu" id="kpi-delta-total">—</div>
          </div>
          <div class="kpi-num" id="kpi-total">—</div>
          <div class="kpi-label">DNS Queries Analysed</div>
          <div class="kpi-sub" id="kpi-total-sub">—</div>
        </div>
        <div class="kpi-card red">
          <div class="kpi-top">
            <div class="kpi-icon"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
            <div class="kpi-delta up" id="kpi-delta-tunnel">—</div>
          </div>
          <div class="kpi-num" id="kpi-tunnel">—</div>
          <div class="kpi-label">Tunnel Signatures Detected</div>
          <div class="kpi-sub" id="kpi-tunnel-sub">—</div>
        </div>
        <div class="kpi-card amb">
          <div class="kpi-top">
            <div class="kpi-icon"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div>
            <div class="kpi-delta up" id="kpi-delta-risk">—</div>
          </div>
          <div class="kpi-num" id="kpi-risk">—</div>
          <div class="kpi-label">Average Risk Score</div>
          <div class="kpi-sub" id="kpi-risk-sub">— / 100 maximum</div>
        </div>
        <div class="kpi-card grn">
          <div class="kpi-top">
            <div class="kpi-icon"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>
            <div class="kpi-delta neu" id="kpi-delta-hosts">—</div>
          </div>
          <div class="kpi-num" id="kpi-hosts">—</div>
          <div class="kpi-label">Unique Source Hosts</div>
          <div class="kpi-sub" id="kpi-hosts-sub">— flagged suspicious</div>
        </div>
      </div>
      <div class="ov-grid">
        <div class="ov-card">
          <div class="ov-card-head">
            <div>
              <div class="ov-card-title">Assessment Summary</div>
              <div class="ov-card-sub" id="assess-sub">The dashboard will highlight the main findings once analysis completes.</div>
            </div>
            <div class="assess-chip ok" id="assess-chip">
              <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              Awaiting Data
            </div>
          </div>
          <div class="assess-body" id="assess-body">Upload a PCAP to generate a readable risk summary.</div>
          <div class="assess-meta">
            <div class="assess-stat"><div class="assess-stat-label">Tunnel Queries</div><div class="assess-stat-value" id="assess-tunnels">—</div></div>
            <div class="assess-stat"><div class="assess-stat-label">High Risk</div><div class="assess-stat-value" id="assess-high">—</div></div>
            <div class="assess-stat"><div class="assess-stat-label">Flagged Hosts</div><div class="assess-stat-value" id="assess-hosts">—</div></div>
            <div class="assess-stat"><div class="assess-stat-label">Decision Threshold</div><div class="assess-stat-value" id="assess-threshold">50</div></div>
          </div>
          <div class="assess-points" id="assess-points">
            <div class="assess-point">
              <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M12 4h9"/><path d="M4 9h16"/><path d="M4 15h16"/></svg>
              <span>Upload and analyse a capture to see the detector verdict, strongest signals, and the hosts driving suspicious activity.</span>
            </div>
          </div>
          <div class="assess-actions">
            <div class="hbtn" onclick="activateView('alerts')"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Review Alerts</div>
            <div class="hbtn" onclick="activateView('features')"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Feature Analysis</div>
          </div>
        </div>
        <div class="mini-grid">
          <div class="ov-card">
            <div class="ov-card-head"><div><div class="ov-card-title">Key Findings</div><div class="ov-card-sub" id="insight-sub">Highest-priority DNS queries.</div></div></div>
            <div class="mini-list" id="overview-top-alerts"><div class="mini-empty">Flagged queries will appear here after analysis.</div></div>
          </div>
          <div class="ov-card">
            <div class="ov-card-head"><div><div class="ov-card-title">Active Hosts</div><div class="ov-card-sub" id="host-insight-sub">Source systems contributing most to detected traffic.</div></div></div>
            <div class="mini-list" id="overview-top-hosts"><div class="mini-empty">Host summaries will appear here after analysis.</div></div>
          </div>
        </div>
      </div>
      <div class="chart-row r2">
        <div class="chart-card">
          <div class="cc-head"><div><div class="cc-title">Query Volume Timeline</div><div class="cc-sub" id="cc-timeline-sub">Packets over time</div></div><div class="cc-badge">Current View</div></div>
          <div class="chart-wrap tall"><canvas id="ch-timeline"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="cc-head"><div><div class="cc-title">Risk Distribution</div><div class="cc-sub">By classification</div></div></div>
          <div class="chart-wrap donut"><canvas id="ch-donut"></canvas></div>
          <div class="legend" id="donut-legend"></div>
        </div>
      </div>
      <div class="chart-row r3">
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">Record Types</div><div class="cc-sub">Query breakdown</div></div>
          <div class="chart-wrap short"><canvas id="ch-types"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">Entropy Distribution</div><div class="cc-sub">Subdomain entropy</div></div>
          <div class="chart-wrap short"><canvas id="ch-entropy"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">Top Source IPs</div><div class="cc-sub">By query count</div></div>
          <div class="chart-wrap short"><canvas id="ch-hosts"></canvas></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ALERTS -->
  <div id="view-alerts" class="view">
    <div class="view-pad">
      <div class="vh">
        <div class="vh-left">
          <div class="vh-eyebrow">Threat Signatures</div>
          <div class="vh-title">Alert Log</div>
          <div class="vh-sub">All flagged DNS queries — click any row for the full 27-feature signal breakdown</div>
        </div>
      </div>
      <div class="tbl-toolbar">
        <div class="srch-wrap">
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" id="qsrch" placeholder="Search queries, IPs, domains, subdomains…" oninput="filterTable()"/>
        </div>
        <div class="filt-btn on" id="filt-tunnel" onclick="toggleFilter('tunnel')">
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
          Tunnels
        </div>
        <div class="filt-btn" id="filt-high" onclick="toggleFilter('high')">High Risk</div>
        <div class="filt-btn" id="filt-all" onclick="toggleFilter('all')">Show All</div>
        <div class="tbl-info" id="tbl-count">0 results</div>
      </div>
      <div class="tbl-wrap">
        <table class="atbl">
          <thead>
            <tr>
              <th onclick="sortTable('query')" title="The full website address the device was trying to look up">Query Domain <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M7 16V4m0 0L3 8m4-4l4 4M17 8v12m0 0l4-4m-4 4l-4-4"/></svg></th>
              <th onclick="sortTable('subdomain')" title="The first part of the query — this is where hidden data is often encoded">Subdomain</th>
              <th onclick="sortTable('src_ip')" title="IP address of the device that sent this DNS request">Source IP</th>
              <th onclick="sortTable('record_type')" title="The type of DNS record requested — TXT, NULL and MX are commonly abused for tunneling">Type</th>
              <th onclick="sortTable('risk_score')" title="Combined threat score from 0 (safe) to 100 (critical). Scores ≥ 50 are flagged as tunnel traffic.">Risk Score <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M7 16V4m0 0L3 8m4-4l4 4M17 8v12m0 0l4-4m-4 4l-4-4"/></svg></th>
              <th title="Final verdict — TUNNEL means the query crossed the detection threshold">Classification</th>
              <th onclick="sortTable('subdomain_entropy')" title="How random the subdomain looks (0–5). High values suggest encoded data — tunneling tools often produce values above 3.8.">Randomness</th>
              <th onclick="sortTable('subdomain_length')" title="Character length of the subdomain label. Normal hostnames are short; tunneling tools use very long subdomains (> 45 chars) to carry data.">Sub Length</th>
              <th onclick="sortTable('hex_ratio')" title="Fraction of subdomain characters that are hexadecimal (0–9, a–f). A high ratio suggests binary data encoded as hex.">Hex Chars %</th>
              <th title="Click to see the full 27-signal breakdown for this query">Details</th>
            </tr>
          </thead>
          <tbody id="alert-tbody"></tbody>
        </table>
        <div id="alert-empty" class="tbl-empty" style="display:none">
          <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M9 12h6M12 9v6"/><circle cx="12" cy="12" r="10"/></svg>
          <div>No alerts match your filter</div>
        </div>
      </div>
    </div>
  </div>

  <!-- FEATURE ANALYSIS -->
  <div id="view-features" class="view">
    <div class="view-pad">
      <div class="vh">
        <div class="vh-left">
          <div class="vh-eyebrow">Detector Signals</div>
          <div class="vh-title">Feature Analysis</div>
          <div class="vh-sub">Deep dive into the 10 machine-learning features and 4 rule-based thresholds used by the detection engine to score every DNS query</div>
        </div>
      </div>
      <!-- Feature stat cards -->
      <div class="feat-row" id="feat-stat-cards"></div>
      <!-- Threshold exceedance table -->
      <div class="thresh-summary">
        <div class="thresh-summary-head">
          <div class="thresh-summary-title">Rule-Based Threshold Exceedances</div>
          <div class="cc-badge">4 Heuristic Rules · 50% of Risk Score</div>
        </div>
        <table class="thresh-tbl">
          <thead>
            <tr>
              <th>Feature</th>
              <th>Threshold</th>
              <th>Queries Exceeded</th>
              <th>% of Total</th>
              <th>Weight</th>
            </tr>
          </thead>
          <tbody id="thresh-tbl-body"></tbody>
        </table>
      </div>
      <!-- Feature distribution charts -->
      <div class="chart-row r3">
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">Subdomain Length</div><div class="cc-sub">Distribution · threshold &gt;45</div></div>
          <div class="chart-wrap short"><canvas id="ch-sublen"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">Hex Character Ratio</div><div class="cc-sub">Subdomain hex density</div></div>
          <div class="chart-wrap short"><canvas id="ch-hexratio"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">Query Length</div><div class="cc-sub">Full query string length</div></div>
          <div class="chart-wrap short"><canvas id="ch-qlen"></canvas></div>
        </div>
      </div>
      <div class="chart-row r2">
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">ML Score vs Rule Hits</div><div class="cc-sub">Anomaly score distribution per rule hit count</div></div>
          <div class="chart-wrap tall"><canvas id="ch-mlrule"></canvas></div>
        </div>
        <div class="chart-card">
          <div class="cc-head"><div class="cc-title">Digit Ratio Distribution</div><div class="cc-sub">Ratio of digits in query</div></div>
          <div class="chart-wrap tall"><canvas id="ch-digitratio"></canvas></div>
        </div>
      </div>
    </div>
  </div>

  <!-- HOSTS -->
  <div id="view-hosts" class="view">
    <div class="view-pad">
      <div class="vh">
        <div class="vh-left">
          <div class="vh-eyebrow">Network Inventory</div>
          <div class="vh-title">Source Hosts</div>
          <div class="vh-sub">Full behavioural profile per source IP — all per-source signals from the detection engine</div>
        </div>
      </div>
      <div class="host-grid" id="host-grid"></div>
      <div id="host-empty" class="panel-empty" style="display:none">
        <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        <h3>No host data yet</h3>
        <p>Upload and analyse a PCAP file to see per-host traffic profiles.</p>
      </div>
    </div>
  </div>

  <!-- LIVE FEED -->
  <div id="view-live" class="view">
    <div class="view-pad">
      <div class="vh">
        <div class="vh-left">
          <div class="vh-eyebrow">Real-Time Monitor</div>
          <div class="vh-title">Live Event Feed</div>
          <div class="vh-sub" id="live-feed-sub">Waiting for live data from pcap_detector.py — start the detector with <code style="font-family:var(--mono);font-size:12px;background:var(--cy3);border-radius:4px;padding:2px 6px">--live --iface eth0</code> and configure it to push to this dashboard.</div>
        </div>
        <div style="margin-left:auto;display:flex;gap:10px;align-items:center">
          <div id="live-mode-indicator" style="display:none;align-items:center;gap:8px;background:var(--grn3);border:1px solid rgba(46,122,84,.16);border-radius:999px;padding:8px 14px;font-size:11px;font-weight:700;color:var(--grn);font-family:var(--mono);letter-spacing:.04em">
            <div class="live-dot"></div>LIVE CAPTURE
          </div>
          <button class="hbtn" onclick="clearLiveFeed()" title="Clear feed">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
            Clear Feed
          </button>
        </div>
      </div>
      <!-- Live stats bar -->
      <div id="live-stats-row">
        <div class="kpi-card"><div class="kpi-icon" style="background:var(--cy2);color:var(--cy)"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div><div class="kpi-body"><div class="kpi-val" id="live-stat-total">0</div><div class="kpi-label">Total Seen</div><div class="kpi-sub">queries this session</div></div></div>
        <div class="kpi-card"><div class="kpi-icon" style="background:var(--red2);color:var(--red)"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg></div><div class="kpi-body"><div class="kpi-val" id="live-stat-tunnel">0</div><div class="kpi-label">Tunnels</div><div class="kpi-sub">score ≥ 50</div></div></div>
        <div class="kpi-card"><div class="kpi-icon" style="background:var(--red2);color:var(--red)"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div><div class="kpi-body"><div class="kpi-val" id="live-stat-high">0</div><div class="kpi-label">High Risk</div><div class="kpi-sub">score ≥ 60</div></div></div>
        <div class="kpi-card"><div class="kpi-icon" style="background:var(--amb2);color:var(--amb)"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div><div class="kpi-body"><div class="kpi-val" id="live-stat-medium">0</div><div class="kpi-label">Medium Risk</div><div class="kpi-sub">score 30–59</div></div></div>
        <div class="kpi-card"><div class="kpi-icon" style="background:var(--grn2);color:var(--grn)"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg></div><div class="kpi-body"><div class="kpi-val" id="live-stat-low">0</div><div class="kpi-label">Low / Clean</div><div class="kpi-sub">score &lt; 30</div></div></div>
      </div>
      <!-- Feed list -->
      <div class="tbl-wrap">
        <div style="padding:16px 20px;border-bottom:1px solid var(--bord);display:flex;align-items:center;justify-content:space-between;gap:12px">
          <div style="font-family:var(--syne);font-size:14px;font-weight:700;color:var(--txt)">Incoming Events</div>
          <div style="font-size:11px;color:var(--t3);font-family:var(--mono)" id="live-feed-count">No events yet</div>
        </div>
        <div id="live-feed-list" style="max-height:520px;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px">
          <div id="live-feed-empty" style="text-align:center;padding:48px 20px;color:var(--t3)">
            <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="width:36px;height:36px;margin:0 auto 12px;display:block"><circle cx="12" cy="12" r="10"/><path d="M10 15l5-3-5-3z"/></svg>
            <div style="font-size:14px;font-weight:600;margin-bottom:4px">Waiting for live events</div>
            <div style="font-size:12px">Once pcap_detector.py pushes events, they will appear here in real time.</div>
          </div>
        </div>
      </div>

      <!-- How to connect instructions -->
      <div class="set-card">
        <div class="set-card-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>How to connect the detector to this dashboard</div>
        <div style="font-size:12px;color:var(--t2);line-height:1.8">Add the following snippet to <code style="font-family:var(--mono);font-size:11px;background:var(--cy3);border-radius:4px;padding:1px 5px">pcap_detector.py</code> inside the <code style="font-family:var(--mono);font-size:11px;background:var(--cy3);border-radius:4px;padding:1px 5px">handle_packet</code> callback. Every scored DNS event will stream to the Live Feed tab automatically.</div>
        <pre style="background:var(--bg3);border:1px solid var(--bord);border-radius:12px;padding:16px;font-family:var(--mono);font-size:11px;line-height:1.75;overflow-x:auto;color:var(--txt);margin:0">import requests, threading

def _push_to_dashboard(row, tracker, iface, window_secs):
    try:
        requests.post("http://127.0.0.1:8080/live/push", json={
            "event":          row.to_dict() if hasattr(row, "to_dict") else dict(row),
            "tracker":        {ip: {k: str(v) for k, v in info.items()}
                               for ip, info in tracker.get_all().items()},
            "interface":      iface,
            "window_seconds": window_secs,
        }, timeout=1)
    except Exception:
        pass  # dashboard offline — detection continues uninterrupted

# Call inside handle_packet() after scoring:
threading.Thread(target=_push_to_dashboard,
    args=(scored_row, tracker, interface, window_seconds),
    daemon=True).start()</pre>
      </div>
    </div>
  </div>

  <!-- CONFIRMED TUNNELS -->
  <div id="view-tunnels" class="view">
    <div class="view-pad">
      <div class="vh">
        <div class="vh-left">
          <div class="vh-eyebrow">Threat Registry</div>
          <div class="vh-title">Confirmed Tunnel Sources</div>
          <div class="vh-sub">Every device on your network confirmed to be hiding data inside DNS traffic — updated automatically in live mode, or populated from offline analysis.</div>
        </div>
        <div style="margin-left:auto">
          <button class="hbtn cy" onclick="exportTunnelCSV()">
            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
            Export
          </button>
        </div>
      </div>

      <!-- What is DNS tunneling? Plain-English explainer -->
      <div style="background:var(--bg2);border:1px solid var(--bord);border-radius:var(--r12);padding:20px 24px;display:flex;gap:20px;align-items:flex-start">
        <div style="flex-shrink:0;width:44px;height:44px;border-radius:12px;background:var(--red2);display:flex;align-items:center;justify-content:center;color:var(--red)">
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width:22px;height:22px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </div>
        <div>
          <div style="font-family:var(--syne);font-size:14px;font-weight:700;margin-bottom:6px">What does "DNS tunneling" mean?</div>
          <div style="font-size:13px;color:var(--t2);line-height:1.75">DNS is the internet's "phone book" — normally used only to look up website addresses. DNS tunneling is a technique where someone secretly encodes other data (files, commands, stolen information) inside those look-up requests to sneak it past firewalls. Each device listed below was caught doing exactly that.</div>
        </div>
      </div>

      <!-- Summary bar -->
      <div id="tunnel-summary-cards"></div>

      <!-- Tunnel IP cards -->
      <div id="tunnel-ip-grid" style="display:flex;flex-direction:column;gap:16px"></div>
      <div id="tunnel-empty" style="text-align:center;padding:64px 20px;color:var(--t3);display:none">
        <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="width:42px;height:42px;margin:0 auto 14px"><polyline points="20 6 9 17 4 12"/></svg>
        <div style="font-size:15px;font-weight:700;margin-bottom:6px;color:var(--grn)">No confirmed tunnels yet</div>
        <div style="font-size:13px">Run a PCAP analysis or start live capture mode to populate this registry.</div>
      </div>
    </div>
  </div>

  <!-- SETTINGS -->
  <div id="view-settings" class="view">
    <div class="view-pad">
      <div class="vh">
        <div class="vh-left">
          <div class="vh-eyebrow">Analysis Configuration</div>
          <div class="vh-title">Detection Settings</div>
          <div class="vh-sub">Thresholds, model parameters, and detection methodology used by the analysis engine</div>
        </div>
      </div>
      <div class="settings-grid">
        <div class="set-card">
          <div class="set-card-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 8h16M4 12h16M4 16h12"/></svg>Heuristic Thresholds</div>
          <div id="thresh-body"></div>
        </div>
        <div class="set-card">
          <div class="set-card-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>Risk Score Formula</div>
          <div class="score-formula">
            <div class="sf-part"><span>50%</span><span>RULE ENGINE</span></div>
            <div class="sf-op">+</div>
            <div class="sf-part"><span>50%</span><span>ML ANOMALY</span></div>
            <div class="sf-op">=</div>
            <div class="sf-part"><span>0–100</span><span>RISK SCORE</span></div>
          </div>
          <div class="thr-row"><span class="thr-key">Tunnel threshold</span><span class="thr-val">≥ 50</span></div>
          <div class="thr-row"><span class="thr-key">High risk threshold</span><span class="thr-val">≥ 60</span></div>
          <div class="thr-row"><span class="thr-key">ML feature dimensions</span><span class="thr-val">10</span></div>
          <div class="thr-row"><span class="thr-key">ML contamination param</span><span class="thr-val">0.25</span></div>
          <div class="thr-row"><span class="thr-key">Isolation Forest estimators</span><span class="thr-val">200</span></div>
        </div>
        <div class="set-card full">
          <div class="set-card-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>Detection Methodology</div>
          <div id="mth-list"></div>
        </div>
        <div class="set-card full">
          <div class="set-card-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>ML Feature Space (10 Dimensions)</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px" id="ml-features-list"></div>
        </div>
      </div>
    </div>
  </div>

</div><!-- /#page -->

<!-- SCAN OVERLAY -->
<div id="scan-overlay">
  <div class="sc-top">
    <div class="sc-badge">Analysis in progress · DNSGuard</div>
    <div class="sc-filename" id="sc-fname">loading.pcap</div>
  </div>
  <div class="sc-center">
    <div class="sc-ring-wrap">
      <svg class="sc-ring-svg" viewBox="0 0 120 120">
        <circle class="sc-ring-track" cx="60" cy="60" r="54"/>
        <circle class="sc-ring-fill" id="sc-ring" cx="60" cy="60" r="54"/>
      </svg>
      <div class="sc-pct"><div class="sc-pct-num" id="sc-pct-num">0</div><div class="sc-pct-lbl">PERCENT</div></div>
    </div>
    <div class="sc-bar-wrap">
      <div class="sc-bar-track"><div class="sc-bar-fill" id="sc-bar"></div></div>
      <div class="sc-msg-wrap">
        <div class="sc-msg-current" id="sc-msg">Initialising analysis engine</div>
        <div class="sc-msg-sub" id="sc-sub">Please wait…</div>
      </div>
    </div>
    <div class="sc-stages" id="sc-stages"></div>
  </div>
</div>

<!-- DRAWER -->
<div id="drawer-overlay" onclick="closeDrawer()">
  <div id="drawer" onclick="event.stopPropagation()">
    <div class="drw-hdr">
      <div class="drw-icon" id="drw-icon"></div>
      <div class="drw-hdr-info">
        <div class="drw-query-text" id="drw-query"></div>
        <div class="drw-query-sub" id="drw-query-sub"></div>
      </div>
      <div class="drw-close" onclick="closeDrawer()">
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </div>
    </div>
    <div id="drw-body"></div>
  </div>
</div>

<!-- TOASTS -->
<div id="toasts"></div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let G = {
  data: null, pcap: '', version: 0,
  sort: { col: 'risk_score', asc: false },
  filter: 'tunnel', search: '',
  charts: {},
  thresholds: {},
  summary: null,
  analytics: null,
  overviewMode: 'tunnel',
  live: { mode:'offline', events:[], tracker:{}, stats:{total:0,high:0,medium:0,low:0,tunnel:0}, version:0, interface:'', started_at:null }
};
let _filteredRows = [];
const MAX_VISIBLE_LIVE_EVENTS = __MAX_VISIBLE_LIVE_EVENTS__;

// ── Risk colour helpers — replace 6+ repeated ternary chains ──────────────────
function riskCol(s)      { return s>=60?'var(--red)':s>=30?'var(--amb)':'var(--grn)'; }
function riskBg(s)       { return s>=60?'var(--red2)':s>=30?'var(--amb2)':'var(--grn2)'; }
function riskCls(s)      { return s>=60?'bad':s>=30?'warn':''; }
function riskBadgeCls(s) { return s>=60?'hi':s>=30?'med':'lo'; }
function riskGrad(s)     { return s>=60?'linear-gradient(90deg,var(--red),#ff6680)':s>=30?'linear-gradient(90deg,var(--amb),#ffcc00)':'linear-gradient(90deg,var(--grn),#7fffd4)'; }

// ── Scan stages ───────────────────────────────────────────────────────────────
const STAGES = [
  { pct: 5,  msg: 'Initialising analysis engine',         sub: 'Loading ML models and rule sets' },
  { pct: 14, msg: 'Transmitting packet capture',          sub: 'Secure local transfer in progress' },
  { pct: 26, msg: 'Parsing PCAP packet structure',        sub: 'Reading Ethernet, IP, and UDP headers' },
  { pct: 39, msg: 'Extracting DNS query records',         sub: 'Filtering UDP port 53 traffic streams' },
  { pct: 51, msg: 'Computing DNS features',               sub: 'Entropy, subdomain length, hex ratio, dot count, digit ratio' },
  { pct: 63, msg: 'Running heuristic rule engine',        sub: '4 threshold checks applied per query' },
  { pct: 74, msg: 'Isolation Forest anomaly detection',   sub: '10-dimensional ML feature space scan' },
  { pct: 84, msg: 'Applying weighted risk scoring',       sub: 'Rule engine 50% · ML model 50%' },
  { pct: 93, msg: 'Classifying tunnel signatures',        sub: 'TUNNEL / NORMAL classification at score ≥ 50' },
  { pct: 100, msg: 'Compiling threat intelligence report', sub: 'Aggregating host profiles and rendering 27-feature dashboard' },
];
let _scanTimer = null, _scanStage = 0, _scanStart = 0;

function buildScanStages() {
  $('sc-stages').innerHTML = STAGES.slice(0,-1).map((s,i) =>
    `<div class="sc-stage" id="ss-${i}"><div class="ss-dot"></div><span class="ss-lbl">${s.msg}</span><span class="ss-time" id="ss-t-${i}"></span></div>`
  ).join('');
}
function setScanProgress(pct, msg, sub) {
  const ring=$('sc-ring'), bar=$('sc-bar'), num=$('sc-pct-num');
  const circ = 2 * Math.PI * 54;
  ring.style.strokeDashoffset = circ * (1 - pct / 100);
  bar.style.width = pct + '%'; num.textContent = Math.round(pct);
  if (msg) $('sc-msg').textContent = msg;
  if (sub) $('sc-sub').textContent = sub;
}
function advanceScanStage(idx) {
  STAGES.slice(0,-1).forEach((_,i)=>{
    const el=$('ss-'+i); if(!el) return;
    el.className='sc-stage'+(i<idx?' done':i===idx?' active':'');
    if(i<idx){ const t=$('ss-t-'+i); if(t&&!t.textContent) t.textContent=((Date.now()-_scanStart)/1000).toFixed(1)+'s'; }
  });
}
function startScanAnimation() {
  _scanStage=0; _scanStart=Date.now(); buildScanStages(); setScanProgress(0,STAGES[0].msg,STAGES[0].sub); advanceScanStage(0); clearTimeout(_scanTimer);
  function tick() { _scanStage++; if(_scanStage>=STAGES.length-1) return; const s=STAGES[_scanStage]; setScanProgress(s.pct,s.msg,s.sub); advanceScanStage(_scanStage); _scanTimer=setTimeout(tick,800+Math.random()*1200); }
  _scanTimer=setTimeout(tick,900);
}
function finishScan() { clearTimeout(_scanTimer); const last=STAGES[STAGES.length-1]; setScanProgress(100,last.msg,last.sub); advanceScanStage(STAGES.length); setTimeout(hideScanOverlay,900); }
function showScanOverlay(name) {
  $('sc-fname').textContent = name;
  const o = $('scan-overlay');
  o.style.display = 'flex';
  requestAnimationFrame(()=>{ requestAnimationFrame(()=>{ o.classList.add('vis'); }); });
  startScanAnimation();
}
function hideScanOverlay() {
  const o = $('scan-overlay');
  o.classList.remove('vis');
  setTimeout(()=>{ o.style.display='none'; }, 320);
}

// ── Upload ────────────────────────────────────────────────────────────────────
const dropZone=document.getElementById('drop-zone'), fileInput=document.getElementById('file-input');
dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('drag-over')});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop',e=>{ e.preventDefault(); dropZone.classList.remove('drag-over'); const f=e.dataTransfer.files[0]; if(f) uploadFile(f); });
fileInput.addEventListener('change',()=>{ if(fileInput.files[0]) uploadFile(fileInput.files[0]); });
dropZone.addEventListener('click',()=>fileInput.click());

function uploadFile(file) {
  const ext = file.name.split('.').pop().toLowerCase();
  if (!['pcap','pcapng','cap'].includes(ext)) {
    toast('Invalid file type — please upload a .pcap, .pcapng, or .cap file', 'warn');
    return;
  }
  showScanOverlay(file.name);
  const fd=new FormData(); fd.append('pcap',file);
  fetch('/analyse',{method:'POST',body:fd})
    .then(async r=>{ const d=await r.json(); if(!r.ok) throw new Error(d.error||`Request failed (${r.status})`); return d; })
    .then(d=>{
      G.data=normalizeRows(Array.isArray(d)?d:(d.data||d.records||[]));
      G.pcap=d.pcap_name||file.name; G.version=d.version||(G.version+1);
      G.thresholds=d.thresholds||{}; G.summary=d.summary||null; G.analytics=null;
      finishScan(); setTimeout(()=>loadDashboard(),100);
    })
    .catch(e=>{ hideScanOverlay(); toast('Upload failed: '+e.message,'warn'); });
}
function resetToUpload() {
  G.data=null; G.pcap=''; G.version=0; G.thresholds={}; G.summary=null; G.analytics=null;
  $set('hd-file','no file loaded');
  $('hd-file').classList.remove('loaded');
  showView('upload'); destroyCharts();
}

function toNum(v) { const n=Number(v); return Number.isFinite(n)?n:0; }

function normalizeRuleReasons(value) {
  if(Array.isArray(value)) return value.filter(Boolean);
  if(typeof value==='string') return value.split(';').map(s=>s.trim()).filter(Boolean);
  return [];
}

function normalizeRows(rows) {
  return (rows||[]).map(raw=>{
    const row={
      ...raw,
      ts: Number.isFinite(Number(raw.ts))?Number(raw.ts):null,
      risk_score: toNum(raw.risk_score),
      subdomain_entropy: toNum(raw.subdomain_entropy),
      hex_ratio: toNum(raw.hex_ratio),
      digit_ratio: toNum(raw.digit_ratio),
      query_rate_per_min: toNum(raw.query_rate_per_min),
      query_length: toNum(raw.query_length),
      subdomain_length: toNum(raw.subdomain_length),
      dot_count: toNum(raw.dot_count),
      ml_score: toNum(raw.ml_score),
      response_size: toNum(raw.response_size),
      rule_hits: toNum(raw.rule_hits),
      rule_reasons: normalizeRuleReasons(raw.rule_reasons),
      // per-source behavioral features
      query_count: toNum(raw.query_count),
      unique_domains: toNum(raw.unique_domains),
      avg_qlen: toNum(raw.avg_qlen),
      avg_entropy: toNum(raw.avg_entropy),
      avg_response: toNum(raw.avg_response),
      special_type_count: toNum(raw.special_type_count),
      is_special_type: toNum(raw.is_special_type),
      subdomain: raw.subdomain||'',
      sport: raw.sport||'',
    };
    Object.defineProperty(row,'__search',{
      value:`${row.query||''} ${row.src_ip||''} ${row.dst_ip||''} ${row.record_type||''} ${row.subdomain||''}`.toLowerCase(),
      enumerable:false
    });
    return row;
  });
}

const _analyticsCache = new WeakMap();
function getAnalytics(rows) {
  if(_analyticsCache.has(rows)) return _analyticsCache.get(rows);
  const analytics={
    rows, total:rows.length, tunnels:0, hiRisk:0, medRisk:0, loRisk:0, riskSum:0,
    hosts:new Set(), badHosts:new Set(), recordTypes:{}, hostStats:{}, hostCounts:{}, hostTunnelCounts:{},
    entropyBuckets: new Array(10).fill(0),
    entropyLabels: Array.from({length:10},(_,i)=>(i/2).toFixed(1)),
    sublenBuckets: new Array(10).fill(0),
    hexBuckets: new Array(10).fill(0),
    qlenBuckets: new Array(10).fill(0),
    digitBuckets: new Array(10).fill(0),
    ruleMlBoxes: [[], [], [], [], []],
    featStats: { entropy:{sum:0,max:0,over:0}, sublen:{sum:0,max:0,over:0}, hexratio:{sum:0,max:0}, qrate:{sum:0,max:0,over:0}, specialtype:{sum:0,max:0,over:0}, digitratio:{sum:0,max:0}, dotcount:{sum:0,max:0}, qlength:{sum:0,max:0}, mlscore:{sum:0,max:0}, riskscore:{sum:0,max:0} },
  };
  rows.forEach(row=>{
    const score=row.risk_score, ip=row.src_ip||'Unknown', rt=row.record_type||'Unknown';
    analytics.riskSum+=score; analytics.hosts.add(ip);
    analytics.recordTypes[rt]=(analytics.recordTypes[rt]||0)+1;
    analytics.hostCounts[ip]=(analytics.hostCounts[ip]||0)+1;
    if(row.prediction==='TUNNEL'){ analytics.tunnels++; analytics.badHosts.add(ip); analytics.hostTunnelCounts[ip]=(analytics.hostTunnelCounts[ip]||0)+1; }
    if(score>=60) analytics.hiRisk++;
    else if(score>=30) analytics.medRisk++;
    else analytics.loRisk++;

    // Entropy histogram
    analytics.entropyBuckets[Math.min(Math.floor(Math.min(row.subdomain_entropy,4.99)*2),9)]++;
    // Subdomain length histogram (0-100+ in 10 buckets of 10)
    analytics.sublenBuckets[Math.min(Math.floor(row.subdomain_length/10),9)]++;
    // Hex ratio histogram (0-1 in 10 buckets)
    analytics.hexBuckets[Math.min(Math.floor(row.hex_ratio*10),9)]++;
    // Query length histogram (0-200+ in 10 buckets of 20)
    analytics.qlenBuckets[Math.min(Math.floor(row.query_length/20),9)]++;
    // Digit ratio histogram
    analytics.digitBuckets[Math.min(Math.floor(row.digit_ratio*10),9)]++;
    // Rule hits vs ML score
    const rh=Math.min(row.rule_hits,4);
    analytics.ruleMlBoxes[rh].push(row.ml_score);

    // Feature stats
    const fs=analytics.featStats;
    fs.entropy.sum+=row.subdomain_entropy; fs.entropy.max=Math.max(fs.entropy.max,row.subdomain_entropy); if(row.subdomain_entropy>3.8) fs.entropy.over++;
    fs.sublen.sum+=row.subdomain_length; fs.sublen.max=Math.max(fs.sublen.max,row.subdomain_length); if(row.subdomain_length>45) fs.sublen.over++;
    fs.hexratio.sum+=row.hex_ratio; fs.hexratio.max=Math.max(fs.hexratio.max,row.hex_ratio);
    fs.qrate.sum+=row.query_rate_per_min; fs.qrate.max=Math.max(fs.qrate.max,row.query_rate_per_min); if(row.query_rate_per_min>5) fs.qrate.over++;
    fs.specialtype.sum+=row.special_type_count; fs.specialtype.max=Math.max(fs.specialtype.max,row.special_type_count); if(row.special_type_count>10) fs.specialtype.over++;
    fs.digitratio.sum+=row.digit_ratio; fs.digitratio.max=Math.max(fs.digitratio.max,row.digit_ratio);
    fs.dotcount.sum+=row.dot_count; fs.dotcount.max=Math.max(fs.dotcount.max,row.dot_count);
    fs.qlength.sum+=row.query_length; fs.qlength.max=Math.max(fs.qlength.max,row.query_length);
    fs.mlscore.sum+=row.ml_score; fs.mlscore.max=Math.max(fs.mlscore.max,row.ml_score);
    fs.riskscore.sum+=score; fs.riskscore.max=Math.max(fs.riskscore.max,score);

    if(!analytics.hostStats[ip]) analytics.hostStats[ip]={total:0,tunnels:0,scoreSum:0,types:new Set(),qrateMax:0,entropyAvg:0,hexAvg:0,qlenAvg:0,responseAvg:0,specialCount:0,uniqueDomains:0};
    const hs=analytics.hostStats[ip];
    hs.total++; hs.scoreSum+=score; if(row.prediction==='TUNNEL') hs.tunnels++;
    if(row.record_type) hs.types.add(row.record_type);
    hs.qrateMax=Math.max(hs.qrateMax,row.query_rate_per_min);
    hs.entropyAvg+=row.subdomain_entropy; hs.hexAvg+=row.hex_ratio;
    hs.qlenAvg+=row.query_length; hs.responseAvg+=row.response_size;
    hs.specialCount=Math.max(hs.specialCount,row.special_type_count);
    hs.uniqueDomains=Math.max(hs.uniqueDomains,row.unique_domains||0);
  });

  // Finalize per-host averages
  Object.values(analytics.hostStats).forEach(hs=>{
    if(hs.total){ hs.entropyAvg/=hs.total; hs.hexAvg/=hs.total; hs.qlenAvg/=hs.total; hs.responseAvg/=hs.total; }
  });

  analytics.avgRisk=analytics.total?Math.round(analytics.riskSum/analytics.total):0;
  analytics.hostCount=analytics.hosts.size; analytics.badHostCount=analytics.badHosts.size;
  analytics.timeline=buildTimeline(rows,20);
  analytics.topRecordTypes=Object.keys(analytics.recordTypes).sort((a,b)=>analytics.recordTypes[b]-analytics.recordTypes[a]).slice(0,6);
  analytics.topHostKeys=Object.keys(analytics.hostCounts).sort((a,b)=>analytics.hostCounts[b]-analytics.hostCounts[a]).slice(0,7);
  analytics.sortedHosts=Object.entries(analytics.hostStats).sort((a,b)=>b[1].tunnels-a[1].tunnels||b[1].total-a[1].total);
  analytics.topAlerts=rows.slice().sort((a,b)=>(b.prediction==='TUNNEL'?1:0)-(a.prediction==='TUNNEL'?1:0)||b.risk_score-a.risk_score).slice(0,6);
  analytics.clean=Math.max(0,analytics.total-analytics.tunnels);
  G.analytics=analytics; _analyticsCache.set(rows, analytics); return analytics;
}

function getOverviewRows(rows) {
  if(G.overviewMode!=='tunnel') return {rows,label:'All Traffic',fallback:false};
  const tunnelRows=rows.filter(r=>r.prediction==='TUNNEL');
  if(tunnelRows.length) return {rows:tunnelRows,label:'Tunnels Only',fallback:false};
  return {rows,label:'All Traffic',fallback:true};
}

// ── Dashboard Load ─────────────────────────────────────────────────────────────
function loadDashboard() {
  const rows=G.data||[];
  const activeTab = document.querySelector('.ntab.on')?.dataset.p;
  const nextView = activeTab && !['upload','live'].includes(activeTab) ? activeTab : 'overview';
  const analytics=getAnalytics(rows);
  const overview=getOverviewRows(rows);
  const overviewAnalytics=overview.rows===rows?analytics:getAnalytics(overview.rows);
  $('hd-file').textContent=G.pcap||'analysis.pcap';
  $('hd-file').classList.add('loaded');
  showView(nextView);
  renderKPIs(analytics);
  renderOverviewInsights(analytics,overviewAnalytics,overview);
  renderCharts(overviewAnalytics,overview);
  renderAlerts(rows);
  renderFeatures(analytics);
  renderHosts(analytics);
  renderSettings(G.thresholds);
  updateBadge(analytics);
  populateTunnelsFromOfflineData(rows);
  toast(`Loaded ${rows.length.toLocaleString()} DNS queries from ${G.pcap}`);
}

// ── KPIs ──────────────────────────────────────────────────────────────────────
function renderKPIs(analytics) {
  const {total,tunnels,hiRisk,avgRisk}=analytics;
  $set('kpi-total',fmt(total)); $set('kpi-tunnel',fmt(tunnels)); $set('kpi-risk',avgRisk); $set('kpi-hosts',analytics.hostCount);
  $set('kpi-total-sub',total?`${((total-tunnels)/total*100).toFixed(1)}% looked normal`:'—');
  $set('kpi-tunnel-sub',total?`${(tunnels/total*100).toFixed(1)}% of all queries flagged`:'—');
  $set('kpi-risk-sub',`${hiRisk} queries scored ≥ 60 (high risk)`);
  $set('kpi-hosts-sub',`${analytics.badHostCount} device${analytics.badHostCount!==1?'s':''} flagged suspicious`);
  $set('kpi-delta-total',total.toLocaleString());
  $set('kpi-delta-tunnel',tunnels?`${tunnels} flagged`:'No flags');
  $('kpi-delta-tunnel').className='kpi-delta '+(tunnels?'up':'ok');
  $set('kpi-delta-risk',avgRisk+'/100'); $set('kpi-delta-hosts',analytics.hostCount+' IPs');
  $set('ov-sub',`Analysed ${G.pcap} · ${new Date().toLocaleString()}`);
}

function renderOverviewInsights(analytics,overviewAnalytics,overview) {
  const modeLabel=overview.label;
  const threshold=(G.summary&&G.summary.tunnel_threshold)||50;
  const tunnelRatio=analytics.total?(analytics.tunnels/analytics.total):0;
  const ovBtn=$('ov-mode-btn');
  if(ovBtn){ const isTunnel=G.overviewMode==='tunnel'; ovBtn.classList.toggle('on',isTunnel); ovBtn.innerHTML=`<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>${isTunnel?'Tunnels Only':'All Traffic'}`; }

  let state='ok',title='Likely clean traffic posture',summary='No strong tunnel indicators were found in this capture. The dashboard remains available for manual review and host-by-host inspection.';
  if(analytics.tunnels>=10||tunnelRatio>=0.15||analytics.hiRisk>=20){ state='critical'; title='Strong indication of DNS tunneling activity'; summary='Multiple DNS queries crossed the tunnel threshold and the capture shows a concentration of high-risk behavior that deserves immediate follow-up.'; }
  else if(analytics.tunnels>0||analytics.hiRisk>0){ state='warn'; title='Suspicious DNS behavior detected'; summary='The detector found a smaller cluster of risky queries. The traffic is not uniformly malicious, but there is enough signal to investigate the highlighted hosts and domains.'; }

  const chip=document.getElementById('assess-chip');
  if(chip){
    const icon=state==='critical'?'<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>':state==='warn'?'<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>':'<path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
    const label=state==='critical'?'High Priority':state==='warn'?'Needs Review':'Likely Clean';
    chip.className=`assess-chip ${state==='critical'?'critical':state==='warn'?'warn':'ok'}`;
    chip.innerHTML=`<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">${icon}</svg>${label}`;
  }
  $set('assess-sub',`Overview mode: ${modeLabel}${overview.fallback?' · no tunnel-only slice available, showing full capture.':'.'}`);
  $set('assess-body',title); $set('assess-tunnels',fmt(analytics.tunnels)); $set('assess-high',fmt(analytics.hiRisk));
  $set('assess-hosts',fmt(analytics.badHostCount)); $set('assess-threshold',threshold);
  const points=[summary,`${fmt(analytics.clean)} of ${fmt(analytics.total)} queries stayed below the tunnel decision threshold, while ${fmt(analytics.hiRisk)} queries reached high-risk scoring.`,`${fmt(overviewAnalytics.topAlerts.length)} top findings and ${fmt(Math.min(overviewAnalytics.sortedHosts.length,4))} host summaries shown below in ${modeLabel.toLowerCase()}.`];
  const pointWrap=document.getElementById('assess-points');
  if(pointWrap) pointWrap.innerHTML=points.map(text=>`<div class="assess-point"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg><span>${esc(text)}</span></div>`).join('');

  $set('insight-sub',`Highest-priority DNS queries from ${modeLabel.toLowerCase()}.`);
  $set('host-insight-sub',`Source systems contributing most to ${modeLabel.toLowerCase()}.`);

  const alertWrap=document.getElementById('overview-top-alerts');
  if(alertWrap){
    const alertRows=overviewAnalytics.topAlerts.slice(0,4);
    alertWrap.innerHTML=alertRows.length?alertRows.map(row=>{
      const score=+row.risk_score||0, sCoreCls=riskCls(score);
      const reason=Array.isArray(row.rule_reasons)&&row.rule_reasons.length?row.rule_reasons[0]:row.prediction==='TUNNEL'?'Elevated by the combined rule and anomaly score.':'Visible in this overview for analyst review.';
      const ds=encodeURIComponent(JSON.stringify(row)).replace(/'/g,'%27');
      return `<div class="mini-item" onclick="openDrawer('${ds}')" style="cursor:pointer"><div class="mini-main"><div class="mini-kicker">${esc(row.src_ip||'Unknown')} · ${esc(row.record_type||'DNS')}</div><div class="mini-title">${esc(row.query||'Unknown query')}</div><div class="mini-sub">${esc(reason)}</div></div><div class="mini-side"><div class="mini-score ${sCoreCls}">${score}</div><span class="risk-badge ${row.prediction==='TUNNEL'?'hi':riskBadgeCls(score)}">${row.prediction==='TUNNEL'?'Tunnel':row.risk_level||'Review'}</span></div></div>`;
    }).join(''):'<div class="mini-empty">No findings available for the current overview mode.</div>';
  }

  const hostWrap=document.getElementById('overview-top-hosts');
  if(hostWrap){
    const hosts=overviewAnalytics.sortedHosts.slice(0,4);
    hostWrap.innerHTML=hosts.length?hosts.map(([ip,host])=>{
      const avg=host.total?Math.round(host.scoreSum/host.total):0;
      const descriptor=host.tunnels?`${host.tunnels} tunnel hits across ${host.total} queries`:`${host.total} queries observed, no tunnel verdict`;
      return `<div class="mini-item"><div class="mini-main"><div class="mini-kicker">Source host</div><div class="mini-title">${esc(ip)}</div><div class="mini-sub">${esc(descriptor)} · ${host.types.size} record types.</div></div><div class="mini-side"><div class="mini-score ${riskCls(avg)}">${avg}</div><span class="risk-badge ${host.tunnels?'hi':riskBadgeCls(avg)}">${host.tunnels?'Flagged':'Observed'}</span></div></div>`;
    }).join(''):'<div class="mini-empty">No host summaries available yet.</div>';
  }
}

// ── Charts ────────────────────────────────────────────────────────────────────
const CY='rgba(36,84,215,1)',CY2='rgba(36,84,215,.18)',CY3='rgba(36,84,215,.08)';
const RED='rgba(196,75,64,1)',RED2='rgba(196,75,64,.18)';
const GRN='rgba(46,122,84,1)',GRN2='rgba(46,122,84,.18)';
const AMB='rgba(199,122,24,1)',AMB2='rgba(199,122,24,.18)';
const PUR='rgba(124,58,237,1)',PUR2='rgba(124,58,237,.18)';
const T2='rgba(102,115,133,1)';

const CHART_DEFAULTS={
  responsive:true,maintainAspectRatio:false,
  plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(22,35,54,.94)',borderColor:'rgba(255,255,255,.08)',borderWidth:1,titleColor:'#f8f4ec',bodyColor:'#d8e2f2',titleFont:{family:'IBM Plex Mono',size:11},bodyFont:{family:'IBM Plex Mono',size:10},padding:12,cornerRadius:12}},
  scales:{x:{border:{display:false},grid:{color:'rgba(21,34,53,.05)'},ticks:{color:'#7e8897',font:{family:'IBM Plex Mono',size:9}}},y:{border:{display:false},grid:{color:'rgba(21,34,53,.05)'},ticks:{color:'#7e8897',font:{family:'IBM Plex Mono',size:9}}}}
};

function destroyCharts() { Object.values(G.charts).forEach(c=>{try{c.destroy()}catch(e){}}); G.charts={}; }
function mkChart(id,cfg) { const ctx=document.getElementById(id); if(!ctx) return; if(G.charts[id]){try{G.charts[id].destroy()}catch(e){}} G.charts[id]=new Chart(ctx,cfg); return G.charts[id]; }
// Shorthand for simple bar charts that only differ in labels + dataset colours
function mkBar(id, labels, data, bgFn, borderFn) {
  mkChart(id,{type:'bar',data:{labels,datasets:[{data,backgroundColor:bgFn?labels.map((_,i)=>bgFn(i)):CY2,borderColor:borderFn?labels.map((_,i)=>borderFn(i)):CY,borderWidth:1,borderRadius:3}]},options:{...CHART_DEFAULTS}});
}

function renderCharts(analytics,overview) {
  $set('cc-timeline-sub',`${overview.label} · ${fmt(analytics.total)} DNS queries in view`);
  const tLine=analytics.timeline;
  mkChart('ch-timeline',{type:'line',data:{labels:tLine.labels,datasets:[{label:'All Queries',data:tLine.all,borderColor:CY,backgroundColor:CY3,borderWidth:1.5,fill:true,tension:.4,pointRadius:0,pointHoverRadius:3},{label:'Tunnels',data:tLine.tun,borderColor:RED,backgroundColor:RED2,borderWidth:1.5,fill:true,tension:.4,pointRadius:0,pointHoverRadius:3}]},options:{...CHART_DEFAULTS}});
  mkChart('ch-donut',{type:'doughnut',data:{labels:['High Risk (≥60)','Medium (30–59)','Low (<30)'],datasets:[{data:[analytics.hiRisk,analytics.medRisk,analytics.loRisk],backgroundColor:[RED,AMB,GRN],borderWidth:0,hoverOffset:4}]},options:{...CHART_DEFAULTS,cutout:'68%',plugins:{...CHART_DEFAULTS.plugins,legend:{display:false}}}});
  const dl=document.getElementById('donut-legend'); if(dl) dl.innerHTML=[['High Risk',RED,analytics.hiRisk],['Medium',AMB,analytics.medRisk],['Low',GRN,analytics.loRisk]].map(([l,c,n])=>`<div class="leg-item"><div class="leg-dot" style="background:${c}"></div>${l}: <b>${n}</b></div>`).join('');
  mkChart('ch-types',{type:'bar',data:{labels:analytics.topRecordTypes,datasets:[{data:analytics.topRecordTypes.map(k=>analytics.recordTypes[k]),backgroundColor:CY2,borderColor:CY,borderWidth:1,borderRadius:3}]},options:{...CHART_DEFAULTS,indexAxis:'y'}});
  mkBar('ch-entropy', analytics.entropyLabels, analytics.entropyBuckets,
    i=>i>=8?RED2:i>=6?AMB2:CY2, i=>i>=8?RED:i>=6?AMB:CY);
  mkChart('ch-hosts',{type:'bar',data:{labels:analytics.topHostKeys.map(k=>k.length>13?k.slice(-13):k),datasets:[{label:'Normal',data:analytics.topHostKeys.map(k=>(analytics.hostCounts[k]||0)-(analytics.hostTunnelCounts[k]||0)),backgroundColor:CY2,borderColor:CY,borderWidth:1,borderRadius:3},{label:'Tunnels',data:analytics.topHostKeys.map(k=>analytics.hostTunnelCounts[k]||0),backgroundColor:RED2,borderColor:RED,borderWidth:1,borderRadius:3}]},options:{...CHART_DEFAULTS,indexAxis:'y',scales:{...CHART_DEFAULTS.scales,x:{...CHART_DEFAULTS.scales.x,stacked:true},y:{...CHART_DEFAULTS.scales.y,stacked:true}}}});
}

function buildTimeline(rows,buckets) {
  if(!rows.length) return {labels:[],all:[],tun:[]};
  const withTs=rows.filter(r=>Number.isFinite(r.ts)).slice().sort((a,b)=>a.ts-b.ts);
  if(withTs.length>=2){
    const minTs=withTs[0].ts,maxTs=withTs[withTs.length-1].ts,span=Math.max(maxTs-minTs,1),bucketSize=span/buckets;
    const labels=[],all=new Array(buckets).fill(0),tun=new Array(buckets).fill(0);
    for(let i=0;i<buckets;i++) labels.push(new Date((minTs+bucketSize*i)*1000).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'}));
    withTs.forEach(row=>{ const idx=Math.min(buckets-1,Math.floor((row.ts-minTs)/bucketSize)); all[idx]++; if(row.prediction==='TUNNEL') tun[idx]++; });
    return {labels,all,tun};
  }
  const step=Math.max(1,Math.floor(rows.length/buckets)),labels=[],all=[],tun=[];
  for(let i=0;i<rows.length;i+=step){ const chunk=rows.slice(i,i+step); labels.push(`#${i+1}`); all.push(chunk.length); tun.push(chunk.filter(r=>r.prediction==='TUNNEL').length); }
  return {labels,all,tun};
}

// ── Feature Analysis View ─────────────────────────────────────────────────────
function renderFeatures(analytics) {
  if(!analytics.total) return;
  const fs=analytics.featStats, n=analytics.total, T=G.thresholds||{subdomain_length:45,subdomain_entropy:3.8,query_rate_per_min:5,special_type_count:10};

  // Stat cards
  const cards=[
    {label:'AVG ENTROPY',icon:'M22 12h-4l-3 9L9 3l-3 9H2',val:(fs.entropy.sum/n).toFixed(3),sub:`Max: ${fs.entropy.max.toFixed(3)} · Threshold: >3.8`,color:'cy',pct:Math.min(fs.entropy.over/n*100,100),over:fs.entropy.over},
    {label:'AVG SUBDOMAIN LEN',icon:'M4 8h16M4 12h16M4 16h12',val:Math.round(fs.sublen.sum/n),sub:`Max: ${fs.sublen.max} chars · Threshold: >45`,color:'red',pct:Math.min(fs.sublen.over/n*100,100),over:fs.sublen.over},
    {label:'AVG HEX RATIO',icon:'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',val:(fs.hexratio.sum/n).toFixed(3),sub:`Max: ${fs.hexratio.max.toFixed(3)} (0=none, 1=all hex)`,color:'amb',pct:Math.min(fs.hexratio.sum/n*100,100),over:null},
    {label:'AVG QUERY RATE/MIN',icon:'M13 2L3 14h9l-1 8 10-12h-9l1-8z',val:(fs.qrate.sum/n).toFixed(2),sub:`Max: ${fs.qrate.max.toFixed(2)}/min · Threshold: >5`,color:'red',pct:Math.min(fs.qrate.over/n*100,100),over:fs.qrate.over},
    {label:'AVG ML SCORE',icon:'M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z',val:(fs.mlscore.sum/n).toFixed(3),sub:`Max: ${fs.mlscore.max.toFixed(3)} (Isolation Forest)`,color:'pur',pct:Math.min(fs.mlscore.sum/n*100,100),over:null},
    {label:'AVG RISK SCORE',icon:'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',val:(fs.riskscore.sum/n).toFixed(1),sub:`Max: ${fs.riskscore.max.toFixed(1)} · Tunnel at ≥50`,color:fs.riskscore.sum/n>=50?'red':fs.riskscore.sum/n>=30?'amb':'grn',pct:Math.min(fs.riskscore.sum/n,100),over:analytics.tunnels},
  ];

  const colorMap={cy:'var(--cy)',red:'var(--red)',amb:'var(--amb)',grn:'var(--grn)',pur:'var(--pur)'};
  const bgMap={cy:'var(--cy2)',red:'var(--red2)',amb:'var(--amb2)',grn:'var(--grn2)',pur:'var(--pur2)'};

  $('feat-stat-cards').innerHTML=cards.map(c=>`
    <div class="feat-stat-card">
      <div class="feat-stat-head">
        <div class="feat-stat-label">${c.label}</div>
        <div class="feat-stat-icon" style="background:${bgMap[c.color]};color:${colorMap[c.color]}">
          <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="${c.icon}"/></svg>
        </div>
      </div>
      <div class="feat-stat-val" style="color:${colorMap[c.color]}">${c.val}</div>
      <div class="feat-thresh-bar"><div class="feat-thresh-fill" style="width:${c.pct}%;background:${colorMap[c.color]}"></div></div>
      <div class="feat-stat-sub">${c.sub}${c.over!==null?` · <b style="color:${colorMap[c.color]}">${c.over}</b> queries exceeded`:''}</div>
    </div>`).join('');

  // Threshold exceedance table
  const threshRows=[
    {name:'subdomain_entropy',desc:'How random the subdomain looks — high values (> 3.8) suggest encoded or encrypted data',thr:`> ${T.subdomain_entropy||3.8}`,over:fs.entropy.over,weight:'12.5%'},
    {name:'subdomain_length',desc:'Number of characters in the subdomain label — tunneling tools use very long labels to carry data',thr:`> ${T.subdomain_length||45}`,over:fs.sublen.over,weight:'12.5%'},
    {name:'query_rate_per_min',desc:'How many queries per minute from this device — high rates suggest automated tunneling',thr:`> ${T.query_rate_per_min||5}`,over:fs.qrate.over,weight:'12.5%'},
    {name:'special_type_count',desc:'Count of TXT, NULL, or MX record requests — these types can carry arbitrary data and are abused by tunneling tools',thr:`> ${T.special_type_count||10}`,over:fs.specialtype.over,weight:'12.5%'},
  ];
  $('thresh-tbl-body').innerHTML=threshRows.map(r=>{
    const pct=n?((r.over/n)*100).toFixed(1):'0.0';
    return `<tr>
      <td><div class="feat-name">${r.name}</div><div class="feat-desc">${r.desc}</div></td>
      <td><span class="feat-thr">${r.thr}</span></td>
      <td><span class="feat-hit-badge ${r.over>0?'has':'none'}">${r.over>0?'⚡':''} ${r.over.toLocaleString()} queries</span></td>
      <td><span class="feat-pct">${pct}%</span></td>
      <td><span class="feat-pct">${r.weight} of risk score</span></td>
    </tr>`;
  }).join('');

  // Feature distribution charts
  const sublabels=['0–9','10–19','20–29','30–39','40–49','50–59','60–69','70–79','80–89','90+'];
  mkBar('ch-sublen', sublabels, analytics.sublenBuckets,
    i=>i>=5?RED2:i>=4?AMB2:CY2, i=>i>=5?RED:i>=4?AMB:CY);

  const hexlabels=['0%','10%','20%','30%','40%','50%','60%','70%','80%','90%+'];
  mkBar('ch-hexratio', hexlabels, analytics.hexBuckets,
    i=>i>=7?RED2:i>=5?AMB2:CY2, i=>i>=7?RED:i>=5?AMB:CY);

  const qlabels=['0–19','20–39','40–59','60–79','80–99','100–119','120–139','140–159','160–179','180+'];
  mkBar('ch-qlen', qlabels, analytics.qlenBuckets, null, null);

  // ML score by rule hits (grouped bar)
  const ruleLabels=['0 hits','1 hit','2 hits','3 hits','4 hits'];
  const avgMlPerRule=analytics.ruleMlBoxes.map(arr=>arr.length?(arr.reduce((a,b)=>a+b,0)/arr.length):0);
  const countPerRule=analytics.ruleMlBoxes.map(arr=>arr.length);
  mkChart('ch-mlrule',{type:'bar',data:{labels:ruleLabels,datasets:[{label:'Avg ML Score',data:avgMlPerRule,backgroundColor:[CY2,AMB2,AMB2,RED2,RED2],borderColor:[CY,AMB,AMB,RED,RED],borderWidth:1,borderRadius:4,yAxisID:'y'},{label:'Query Count',data:countPerRule,type:'line',borderColor:T2,backgroundColor:'transparent',borderWidth:1.5,pointRadius:3,tension:.3,yAxisID:'y1'}]},options:{...CHART_DEFAULTS,plugins:{...CHART_DEFAULTS.plugins,legend:{display:true,labels:{color:'#667385',font:{family:'IBM Plex Mono',size:10}}}},scales:{y:{...CHART_DEFAULTS.scales.y,position:'left',title:{display:true,text:'Avg ML Score',color:'#8d97a6',font:{family:'IBM Plex Mono',size:9}}},y1:{position:'right',grid:{drawOnChartArea:false},ticks:{color:'#7e8897',font:{family:'IBM Plex Mono',size:9}},title:{display:true,text:'Query Count',color:'#8d97a6',font:{family:'IBM Plex Mono',size:9}}}}}});

  const dlabels=['0%','10%','20%','30%','40%','50%','60%','70%','80%','90%+'];
  mkBar('ch-digitratio', dlabels, analytics.digitBuckets, null, null);
}

// ── Alerts Table ───────────────────────────────────────────────────────────────
function renderAlerts(rows){ _filteredRows=rows; applyFilter(); }
function applyFilter() {
  const rows=G.data||[], q=(G.search||'').toLowerCase();
  let filtered=rows.filter(r=>{ if(G.filter==='tunnel') return r.prediction==='TUNNEL'; if(G.filter==='high') return +r.risk_score>=60; return true; });
  if(q) filtered=filtered.filter(r=>r.__search.includes(q));
  filtered.sort((a,b)=>{ let va=a[G.sort.col]||'',vb=b[G.sort.col]||''; if(!isNaN(+va)&&!isNaN(+vb)){va=+va;vb=+vb;} if(va<vb) return G.sort.asc?-1:1; if(va>vb) return G.sort.asc?1:-1; return 0; });
  _filteredRows=filtered; renderAlertRows(filtered); $set('tbl-count',filtered.length.toLocaleString()+' results');
}
function renderAlertRows(rows) {
  const tbody=document.getElementById('alert-tbody');
  if(!rows.length){tbody.innerHTML=''; show('alert-empty',true); return;}
  show('alert-empty',false);
  const SPECIAL=['TXT','NULL','MX'];
  tbody.innerHTML=rows.map(r=>{
    const score=+r.risk_score||0, isTun=r.prediction==='TUNNEL';
    const barColor=riskCol(score);
    const badgeTxt=isTun?'TUNNEL':score>=60?'HIGH':score>=30?'MEDIUM':'CLEAN';
    const isSpecial=SPECIAL.includes(r.record_type);
    const ds=encodeURIComponent(JSON.stringify(r)).replace(/'/g,'%27');
    return `<tr onclick="openDrawer('${ds}')">
      <td><div class="td-query" title="${esc(r.query||'')}">${esc(r.query||'—')}</div></td>
      <td><div class="td-sub" title="${esc(r.subdomain||'')}">${esc(r.subdomain||'—')}</div></td>
      <td><div class="td-ip">${esc(r.src_ip||'—')}</div></td>
      <td><span class="td-type${isSpecial?' special':''}">${esc(r.record_type||'?')}</span></td>
      <td><div style="display:flex;align-items:center;gap:7px"><span style="font-family:var(--mono);font-size:11px;font-weight:600;color:${barColor}">${score}</span><div class="score-bar-mini"><div class="score-bar-mini-fill" style="width:${score}%;background:${barColor}"></div></div></div></td>
      <td><span class="risk-badge ${riskBadgeCls(score)}">${badgeTxt}</span></td>
      <td><span style="font-family:var(--mono);font-size:11px;color:var(--t2)" title="Subdomain randomness score (0–5). Values above 3.8 are suspicious.">${(+r.subdomain_entropy||0).toFixed(3)}</span></td>
      <td><span style="font-family:var(--mono);font-size:11px;color:${r.subdomain_length>45?'var(--red)':'var(--t2)'}" title="Length of subdomain label in characters. Over 45 chars is flagged.">${r.subdomain_length||0}</span></td>
      <td><span style="font-family:var(--mono);font-size:11px;color:${r.hex_ratio>0.6?'var(--amb)':'var(--t2)'}" title="Fraction of subdomain made up of hex characters (0–1). Over 0.6 is suspicious.">${(+r.hex_ratio||0).toFixed(2)}</span></td>
      <td><button class="hbtn-sm" onclick="event.stopPropagation();openDrawer('${ds}')"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Details</button></td>
    </tr>`;
  }).join('');
}
function toggleFilter(f) { G.filter=f; ['tunnel','high','all'].forEach(k=>{ const el=document.getElementById('filt-'+k); if(el) el.className='filt-btn'+(k===f?' on':''); }); applyFilter(); }
function filterTable() { G.search=document.getElementById('qsrch').value; applyFilter(); }
function sortTable(col) { if(G.sort.col===col) G.sort.asc=!G.sort.asc; else{G.sort.col=col;G.sort.asc=false;} applyFilter(); }
function updateBadge(analytics) { const n=analytics.tunnels, b=document.getElementById('badge-alerts'); if(b){b.textContent=n;b.className='nbadge'+(n?' show':'');} }

// ── Hosts ─────────────────────────────────────────────────────────────────────
function renderHosts(analytics) {
  const grid=document.getElementById('host-grid');
  if(!analytics.total){grid.innerHTML=''; show('host-empty',true); return;}
  show('host-empty',false);
  const maxTotal=Math.max(...analytics.sortedHosts.map(([,v])=>v.total));
  grid.innerHTML=analytics.sortedHosts.slice(0,24).map(([ip,h])=>{
    const avg=h.total?Math.round(h.scoreSum/h.total):0;
    const pct=Math.round(h.total/maxTotal*100), riskColor=riskCol(avg);
    const tPct=Math.round(h.tunnels/h.total*100);
    const badge=h.tunnels>0?`<span class="risk-badge hi">${h.tunnels} tunnels</span>`:`<span class="risk-badge lo">Clean</span>`;
    const entropyWarn=h.entropyAvg>3.8, hexWarn=h.hexAvg>0.6, qrateWarn=h.qrateMax>5, specialWarn=h.specialCount>10;
    return `<div class="host-card">
      <div class="hc-top"><div class="hc-ip">${esc(ip)}</div>${badge}</div>
      <div class="hc-bar-row">
        <div class="hc-bar-label"><span>Query volume</span><span>${h.total} queries</span></div>
        <div class="hc-bar"><div class="hc-bar-fill" style="width:${pct}%;background:var(--cy)"></div></div>
      </div>
      ${h.tunnels>0?`<div class="hc-bar-row"><div class="hc-bar-label"><span>Tunnel ratio</span><span>${tPct}%</span></div><div class="hc-bar"><div class="hc-bar-fill" style="width:${tPct}%;background:var(--red)"></div></div></div>`:''}
      <div class="hc-stats">
        <div class="hc-stat"><div class="hc-stat-num" style="color:${riskColor}">${avg}</div><div class="hc-stat-lbl">AVG RISK</div></div>
        <div class="hc-stat"><div class="hc-stat-num" style="color:var(--txt)">${h.types.size}</div><div class="hc-stat-lbl">REC TYPES</div></div>
        <div class="hc-stat"><div class="hc-stat-num" style="color:var(--txt)">${h.tunnels}</div><div class="hc-stat-lbl">TUNNELS</div></div>
      </div>
      <div class="hc-divider"></div>
      <div style="font-family:var(--mono);font-size:9px;color:var(--t3);letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">Behavioral Features</div>
      <div class="hc-feat-grid">
        <div class="hc-feat ${entropyWarn?'danger':''}">
          <div class="hc-feat-num">${h.entropyAvg.toFixed(2)}</div>
          <div class="hc-feat-lbl">AVG RANDOMNESS${entropyWarn?' ⚡':''}</div>
        </div>
        <div class="hc-feat ${hexWarn?'warn':''}">
          <div class="hc-feat-num">${(h.hexAvg*100).toFixed(0)}%</div>
          <div class="hc-feat-lbl">HEX CHARS${hexWarn?' ⚡':''}</div>
        </div>
        <div class="hc-feat ${qrateWarn?'danger':''}">
          <div class="hc-feat-num">${h.qrateMax.toFixed(1)}</div>
          <div class="hc-feat-lbl">PEAK Q/MIN${qrateWarn?' ⚡':''}</div>
        </div>
        <div class="hc-feat">
          <div class="hc-feat-num">${Math.round(h.qlenAvg)}</div>
          <div class="hc-feat-lbl">AVG Q LENGTH</div>
        </div>
        <div class="hc-feat">
          <div class="hc-feat-num">${Math.round(h.responseAvg)}</div>
          <div class="hc-feat-lbl">AVG RESP BYTES</div>
        </div>
        <div class="hc-feat ${specialWarn?'danger':''}">
          <div class="hc-feat-num">${h.specialCount}</div>
          <div class="hc-feat-lbl">SPECIAL RECS${specialWarn?' ⚡':''}</div>
        </div>
      </div>
      <div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-top:4px">${h.uniqueDomains} unique domains queried</div>
    </div>`;
  }).join('');
}

// ── Settings ─────────────────────────────────────────────────────────────────
function renderSettings(thresholds) {
  const T=thresholds||{subdomain_length:45,subdomain_entropy:3.8,query_rate_per_min:5,special_type_count:10};
  const TICONS={subdomain_length:'M4 8h16M4 12h16M4 16h12',subdomain_entropy:'M22 12h-4l-3 9L9 3l-3 9H2',query_rate_per_min:'M13 2L3 14h9l-1 8 10-12h-9l1-8z',special_type_count:'M3 6h18M3 12h18M3 18h18'};
  const TLABELS={subdomain_length:'Max subdomain length',subdomain_entropy:'Entropy threshold',query_rate_per_min:'Max queries per minute',special_type_count:'Special record type count'};
  const tb=$('thresh-body');
  if(tb) tb.innerHTML=Object.entries(T).map(([k,v])=>`<div class="thr-row"><span class="thr-key"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="${TICONS[k]||'M12 12h.01'}"/></svg>${TLABELS[k]||k}</span><span class="thr-hint">flag if &gt;</span><span class="thr-val">${v}</span></div>`).join('');

  const METHODS=[
    {c:'var(--cy)',bg:'var(--cy2)',ic:'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4',k:'Rule Engine (4 heuristics)',v:'Four rule-based checks: (1) Subdomain length >45 chars, (2) Shannon entropy >3.8, (3) Query rate >5/min from same source, (4) Special record count (TXT/NULL/MX) >10. Each hit scores 12.5 points toward the 50-point rule half of the risk score.'},
    {c:'var(--grn)',bg:'var(--grn2)',ic:'M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z',k:'Isolation Forest (ML anomaly detection)',v:'Unsupervised model trained across 10 behavioral and lexical features. Scores each query as a normalized anomaly value 0–1. Catches unusual patterns that miss hard rule thresholds. Contamination=0.25, estimators=200, random_state=42.'},
    {c:'var(--red)',bg:'var(--red2)',ic:'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',k:'Weighted Risk Scoring',v:'Final score = (rule_hits/4)×50 + ml_score×50, giving a 0–100 composite threat rating. Score ≥ 50 → classified as TUNNEL. Score ≥ 60 → flagged High Risk. Score 30–59 → Medium Risk. Score <30 → Low Risk.'},
  ];
  const ml=$('mth-list');
  if(ml) ml.innerHTML=METHODS.map(m=>`<div class="mth-item"><div class="mth-dot" style="background:${m.bg};color:${m.c}"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="${m.ic}"/></svg></div><div><div class="mth-key">${m.k}</div><div class="mth-val">${m.v}</div></div></div>`).join('');

  const ML_FEATURES=[
    {name:'query_length',       label:'Query Length',            desc:'Total character length of the full DNS query string — tunneling queries tend to be much longer than normal lookups'},
    {name:'subdomain_length',   label:'Subdomain Length',        desc:'Character length of the leftmost label — normal hostnames are short, but tunneling tools pack data here making it very long'},
    {name:'subdomain_entropy',  label:'Subdomain Randomness',    desc:'How random the subdomain looks (Shannon entropy). High values indicate encoded or encrypted content rather than a real hostname'},
    {name:'dot_count',          label:'Label Count',             desc:'Number of dot-separated parts in the query. Unusually deep nesting can be a tunneling indicator'},
    {name:'digit_ratio',        label:'Digit Density',           desc:'Fraction of the query made up of digits. Encoded data often contains many numbers'},
    {name:'hex_ratio',          label:'Hex Character Density',   desc:'Fraction of the subdomain made up of hexadecimal characters (0–9, a–f). Suggests binary data encoded as hex'},
    {name:'query_count',        label:'Device Query Volume',     desc:'Total DNS queries sent by this device during the capture — unusually high counts are a behavioural signal'},
    {name:'avg_entropy',        label:'Device Avg Randomness',   desc:'Average subdomain randomness across all queries from this device. Consistently high values are a strong tunnel indicator'},
    {name:'query_rate_per_min', label:'Queries Per Minute',      desc:'How fast this device is sending DNS requests. Automated tunneling tools generate much higher rates than a human browsing the web'},
    {name:'avg_response',       label:'Avg Response Size',       desc:'Average DNS response packet size in bytes. Tunneling may inflate response sizes when data is carried back'},
  ];
  const mfl=document.getElementById('ml-features-list');
  if(mfl) mfl.innerHTML=ML_FEATURES.map((f,i)=>`<div style="background:var(--bg2);border:1px solid var(--bord);border-radius:14px;padding:12px 14px;display:flex;flex-direction:column;gap:4px"><div style="font-family:var(--mono);font-size:11px;font-weight:600;color:var(--cy)">[${i+1}] ${f.label}</div><div style="font-size:10px;color:var(--t3);font-family:var(--mono);margin-bottom:2px">${f.name}</div><div style="font-size:11px;color:var(--t2);line-height:1.5">${f.desc}</div></div>`).join('');
}

// ── Drawer ────────────────────────────────────────────────────────────────────
function openDrawer(ds) {
  const r=JSON.parse(decodeURIComponent(ds));
  const score=+r.risk_score||0, isTun=r.prediction==='TUNNEL';
  const reasons=Array.isArray(r.rule_reasons)?r.rule_reasons:String(r.rule_reasons||'').split(';').map(s=>s.trim()).filter(Boolean);
  const col=riskCol(score), bg=riskBg(score), gbg=riskGrad(score);

  $('drw-query').textContent=r.query||'Unknown query';
  $('drw-query-sub').textContent=r.ts?new Date(r.ts*1000).toLocaleString():'';

  const ic=$('drw-icon');
  ic.style.background=bg; ic.style.color=col;
  ic.innerHTML=`<svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width:18px;height:18px"><path d="${isTun?'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01':'M22 11.08V12a10 10 0 11-5.93-9.14M22 4L12 14.01l-3-3'}"/></svg>`;

  $('drw-body').innerHTML=`
    <div class="score-row">
      <div class="score-box">
        <div class="score-num" style="color:${col}">${score}</div>
        <div class="score-lbl">${esc(r.risk_level||'Low')} Risk · out of 100</div>
        <div class="score-track"><div class="score-fill score-fill-bar" style="background:${gbg}"></div></div>
        <div class="score-ticks"><span>0 Safe</span><span>50 Tunnel</span><span>100 Critical</span></div>
      </div>
      <div class="verdict-box">
        <div class="verdict-tag" style="color:${col}">${isTun?'Hidden data detected':'Looks normal'}</div>
        <div class="verdict-sub">${isTun?'This query crossed the tunneling detection threshold. The combined rule checks and anomaly model both indicate suspicious DNS behaviour — this device may be secretly moving data through DNS.':'This query stayed below the detection threshold and does not stand out strongly against the rest of the capture. No immediate action is needed.'}</div>
      </div>
    </div>

    <div class="drw-section">
      <div class="drw-sec-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>Connection Details</div>
      <div class="kv-list">
        ${kv('Source IP', r.src_ip, 'b')}
        ${kv('Source Port', r.sport)}
        ${kv('Destination IP', r.dst_ip)}
        ${kv('Record Type', r.record_type)}
        ${kv('Response Size', (r.response_size||0)+' bytes')}
        ${kv('Timestamp', r.ts?new Date(r.ts*1000).toLocaleString():'—')}
      </div>
      ${r.subdomain?`<div style="margin-top:8px"><div style="font-size:11px;color:var(--t3);font-family:var(--mono);margin-bottom:4px">EXTRACTED SUBDOMAIN LABEL</div><div class="subdomain-pill">${esc(r.subdomain)}</div></div>`:''}
    </div>

    <div class="drw-section">
      <div class="drw-sec-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Query Pattern Analysis</div>
      <div class="mini-score-grid">
        <div class="mscore-box" style="border-color:${r.subdomain_entropy>3.8?'rgba(196,75,64,.2)':'var(--bord)'}">
          <div class="mscore-val" style="color:${r.subdomain_entropy>3.8?'var(--red)':'var(--txt)'}">${fmt2(r.subdomain_entropy)}</div>
          <div class="mscore-lbl">RANDOMNESS · threshold &gt;3.8</div>
        </div>
        <div class="mscore-box" style="border-color:${r.subdomain_length>45?'rgba(196,75,64,.2)':'var(--bord)'}">
          <div class="mscore-val" style="color:${r.subdomain_length>45?'var(--red)':'var(--txt)'}">${r.subdomain_length||0}</div>
          <div class="mscore-lbl">SUBDOMAIN LENGTH · threshold &gt;45</div>
        </div>
        <div class="mscore-box">
          <div class="mscore-val" style="color:${r.hex_ratio>0.6?'var(--amb)':'var(--txt)'}">${fmt2(r.hex_ratio)}</div>
          <div class="mscore-lbl">HEX RATIO (0–1)</div>
        </div>
        <div class="mscore-box">
          <div class="mscore-val" style="color:${r.digit_ratio>0.4?'var(--amb)':'var(--txt)'}">${fmt2(r.digit_ratio)}</div>
          <div class="mscore-lbl">DIGIT RATIO (0–1)</div>
        </div>
      </div>
      <div class="kv-list" style="margin-top:10px">
        ${kv('Query Length', (r.query_length||0)+' chars')}
        ${kv('Dot Count', r.dot_count||0, '', '(labels in query)')}
        ${kv('Is Special Type', r.is_special_type?'Yes (TXT/NULL/MX)':'No', r.is_special_type?'a':'')}
        ${kv('Query Rate / min', fmt2(r.query_rate_per_min), +r.query_rate_per_min>5?'a':'', '· threshold >5')}
      </div>
    </div>

    <div class="drw-section">
      <div class="drw-sec-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>Device Traffic History</div>
      <div class="kv-list">
        ${kv('Total Queries (this device)', fmt(r.query_count||0))}
        ${kv('Unique Domains Queried', fmt(r.unique_domains||0))}
        ${kv('Avg Query Length', fmt2(r.avg_qlen)+' chars')}
        ${kv('Avg Subdomain Randomness', fmt2(r.avg_entropy), +r.avg_entropy>3.5?'a':'')}
        ${kv('Avg Response Size', fmt2(r.avg_response)+' bytes')}
        ${kv('Suspicious Record Count', (r.special_type_count||0)+' records', +r.special_type_count>10?'r':'', '· threshold >10')}
        ${kv('Rule Violations', (r.rule_hits||0)+' / 4 checks triggered')}
        ${kv('Anomaly Model Score', fmt2(r.ml_score), +r.ml_score>0.6?'r':+r.ml_score>0.4?'a':'')}
      </div>
    </div>

    <div class="drw-section">
      <div class="drw-sec-title"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>Why Was This Flagged?</div>
      ${reasons.length
        ? reasons.map(s=>`<div class="rule-item"><div class="rule-dot"><svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div><span>${esc(s.trim())}</span></div>`).join('')
        : '<div class="no-rules">Flagged by the machine-learning anomaly model — the overall pattern of this query is statistically unusual compared to normal traffic, but no individual rule threshold was exceeded. This is typical of low-volume or novel tunneling behaviour that flies under rule-based radars.</div>'
      }
    </div>`;

  const ov=$('drawer-overlay'), dr=$('drawer');
  ov.style.display='block';
  requestAnimationFrame(()=>{ ov.classList.add('vis'); dr.classList.add('open'); });
  setTimeout(()=>{ const f=dr.querySelector('.score-fill-bar'); if(f) f.style.width=score+'%'; },200);
}

function kv(k,v,cls,hint) {
  const safeCls = ['a','b','r'].includes(cls) ? cls : '';
  const safeValue = v == null || v === '' ? '—' : String(v);
  return `<div class="kv"><span class="kv-k">${esc(k)}${hint?` <span style="font-size:9px;color:var(--t3);font-family:var(--mono)">${esc(hint)}</span>`:''}</span><span class="kv-v ${safeCls}">${esc(safeValue)}</span></div>`;
}
function closeDrawer() {
  const ov=$('drawer-overlay'), dr=$('drawer');
  ov.classList.remove('vis'); dr.classList.remove('open');
  setTimeout(()=>{ ov.style.display='none'; },300);
}

// ── Nav ───────────────────────────────────────────────────────────────────────
const FREE_TABS = new Set(['settings','live','tunnels','upload']);
document.querySelectorAll('.ntab').forEach(tab=>{
  tab.addEventListener('click',()=>{
    const p=tab.dataset.p;
    if(!G.data&&!FREE_TABS.has(p)){toast('Upload a PCAP file first','warn');return;}
    document.querySelectorAll('.ntab').forEach(t=>t.classList.toggle('on',t===tab));
    showView(p);
    if(p==='tunnels') renderTunnelIPs(G.live.tracker||{}, G.live.stats||{});
  });
});
function showView(p) {
  document.querySelectorAll('.view').forEach(v => {
    v.classList.remove('on');
    v.style.animation = 'none';
  });
  const el = document.getElementById('view-' + p);
  if (el) {
    el.classList.add('on');
    // Force reflow so animation restarts cleanly on every tab switch
    void el.offsetWidth;
    el.style.animation = '';
  }
  document.querySelectorAll('.ntab').forEach(t => t.classList.toggle('on', t.dataset.p === p));
}
function activateView(p) { if(!G.data&&!FREE_TABS.has(p)){toast('Upload a PCAP file first','warn');return;} showView(p); }

// ── Utils ─────────────────────────────────────────────────────────────────────
function toggleOvMode() {
  G.overviewMode = G.overviewMode === 'tunnel' ? 'all' : 'tunnel';
  const rows=G.data||[], analytics=getAnalytics(rows), overview=getOverviewRows(rows);
  const overviewAnalytics=overview.rows===rows?analytics:getAnalytics(overview.rows);
  renderOverviewInsights(analytics,overviewAnalytics,overview);
  renderCharts(overviewAnalytics,overview);
}
function exportCSV() {
  if(!G.data||!G.data.length){toast('No data to export','warn');return;}
  const keys=Object.keys(G.data[0]);
  const csv=[keys.join(','),...G.data.map(r=>keys.map(k=>JSON.stringify(r[k]??'')).join(','))].join('\n');
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  const a=document.createElement('a'); a.href=url; a.download=G.pcap.replace(/\.[^.]+$/,'')+'-dns-shield.csv';
  a.click(); URL.revokeObjectURL(url);
  toast('Exported '+G.data.length.toLocaleString()+' rows');
}
function $(id){return document.getElementById(id)}
function $set(id,v){const e=$(id);if(e) e.textContent=v;}
function show(id,visible){const e=$(id);if(e) e.style.display=visible?'':'none';}
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}
function fmt(n){return(+n||0).toLocaleString();}
function fmt2(n){return isNaN(+n)?'—':(+n).toFixed(3);}
function mergeLiveEvents(existing,incoming){
  const merged=[], seen=new Set();
  [...(incoming||[]), ...(existing||[])].forEach((ev,idx)=>{
    if(!ev) return;
    const key = ev._event_version!=null ? `v:${ev._event_version}` : JSON.stringify([ev.ts, ev.query, ev.src_ip, ev.risk_score, idx]);
    if(seen.has(key)) return;
    seen.add(key);
    merged.push(ev);
  });
  return merged.slice(0, 200);
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg,type) {
  const c=document.getElementById('toasts'), el=document.createElement('div');
  el.className='toast'+(type==='warn'?' warn':'');
  const ic=type==='warn'?'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4':'M22 11.08V12a10 10 0 11-5.93-9.14M22 4L12 14.01l-3-3';
  el.innerHTML=`<div class="t-icon${type==='warn'?' warn':''}"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="${ic}"/></svg></div><span>${esc(msg)}</span>`;
  c.appendChild(el);
  setTimeout(()=>{ el.style.transition='opacity .2s,transform .2s'; el.style.opacity='0'; el.style.transform='translateX(10px)'; setTimeout(()=>el.remove(),220); },3500);
}

// ── Dark mode ─────────────────────────────────────────────────────────────────
function toggleDark() {
  const isDark = document.body.classList.toggle('dark');
  localStorage.setItem('dns-shield-dark', isDark ? '1' : '0');
  const icon = document.getElementById('dark-icon');
  if (icon) icon.querySelector('path').setAttribute('d', isDark
    ? 'M12 3v1m0 16v1m9-9h-1M4 12H3m15.36-6.36l-.71.71M6.34 17.66l-.7.7M17.66 17.66l-.7-.7M6.34 6.34l-.7-.71M12 5a7 7 0 100 14A7 7 0 0012 5z'
    : 'M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z');
}
(function(){ if(localStorage.getItem('dns-shield-dark')==='1') toggleDark(); })();

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() { const ts=document.getElementById('hd-ts'); if(ts) ts.textContent=new Date().toLocaleTimeString('en-GB',{hour12:false}); }
setInterval(updateClock,1000); updateClock();

// ── Polling — offline results ─────────────────────────────────────────────────
// ── Unified polling loop (offline results + live events, every 2 s) ────────────
let _liveVersion = 0;
async function _poll() {
  // Offline PCAP results
  try {
    const res=await fetch('/results?since='+G.version), d=await res.json();
    if(d.data&&d.version>G.version){
      G.data=normalizeRows(d.data); G.version=d.version;
      G.pcap=d.pcap_name||G.pcap; G.thresholds=d.thresholds||G.thresholds;
      G.summary=d.summary||G.summary; G.analytics=null;
      loadDashboard();
    }
  } catch(e){}
  // Live events — always active
  try {
    const res=await fetch('/live/status?since='+_liveVersion), d=await res.json();
    if(d && d.version>_liveVersion) {
      _liveVersion=d.version;
      const mergedEvents = Array.isArray(d.events) ? d.events : mergeLiveEvents(G.live.events||[], d.new_events||[]);
      G.live={
        mode:d.mode||'offline', events:mergedEvents, tracker:d.tracker||{},
        stats:d.stats||{total:0,high:0,medium:0,low:0,tunnel:0},
        version:d.version, interface:d.interface||'', started_at:d.started_at||null
      };
      applyLiveUpdate();
    }
  } catch(e){}
}
setInterval(_poll, 2000);

function applyLiveUpdate() {
  const L = G.live;
  const isLive = L.mode === 'live';

  // Header pills — 'flex' when visible, '' (block) when hidden via show()
  const pill=$('hd-live-pill'), readyPill=$('hd-ready-pill');
  if(pill){ pill.style.display = isLive ? 'flex' : 'none'; }
  if(readyPill){ readyPill.style.display = isLive ? 'none' : 'flex'; }

  // Nav badges
  function setBadge(id, n) {
    const el=$(id); if(!el) return;
    el.textContent=n; el.classList.toggle('show', n>0);
  }
  setBadge('nb-live', L.stats.tunnel);
  setBadge('nb-tunnels', Object.keys(L.tracker).length);

  // Live feed panel stats
  $set('live-stat-total', fmt(L.stats.total));
  $set('live-stat-tunnel', fmt(L.stats.tunnel));
  $set('live-stat-high', fmt(L.stats.high||0));
  $set('live-stat-medium', fmt(L.stats.medium||0));
  $set('live-stat-low', fmt(L.stats.low||0));

  // Live feed sub-header
  const liveSub = $('live-feed-sub');
  if(liveSub && isLive){
    const iface = L.interface ? ` on <b>${esc(L.interface)}</b>` : '';
    const since = L.started_at ? ` · started ${new Date(L.started_at).toLocaleTimeString()}` : '';
    liveSub.innerHTML = `Capturing live DNS traffic${iface}${since}`;
  }

  // Mode indicator in Live Feed view
  const modeInd = $('live-mode-indicator');
  if(modeInd) modeInd.style.display = isLive ? 'flex' : 'none';

  // Render event feed list
  renderLiveFeed(L.events);

  // Tunnel count update
  $set('live-feed-count', L.events.length ? `${L.events.length} event${L.events.length!==1?'s':''} (newest first)` : 'No events yet');

  // If currently on tunnels tab, refresh
  const tunView = document.getElementById('view-tunnels');
  if(tunView && tunView.classList.contains('on')) renderTunnelIPs(L.tracker, L.stats);
}

function renderLiveFeed(events) {
  const list = document.getElementById('live-feed-list');
  if(!list) return;
  const empty = $('live-feed-empty');
  Array.from(list.children).forEach(c => { if(c !== empty) c.remove(); });

  if(!events || !events.length) {
    show('live-feed-empty', true);
    return;
  }
  show('live-feed-empty', false);

  // Build new card elements (newest events are at index 0)
  const fragment = document.createDocumentFragment();
  events.slice(0, MAX_VISIBLE_LIVE_EVENTS).forEach((ev) => {
    const score = +(ev.risk_score||0);
    const isTun = ev.prediction === 'TUNNEL';
    const level = String(ev.risk_level||'Low');
    const col = riskCol(score), bg = riskBg(score);
    const ts = ev.ts ? new Date(ev.ts*1000).toLocaleTimeString() : '';
    const reasons = Array.isArray(ev.rule_reasons)?ev.rule_reasons:(ev.rule_reasons?[ev.rule_reasons]:[]);
    const reasonText = reasons.length ? reasons[0] : (isTun ? 'Flagged by anomaly model — statistically unusual pattern.' : 'Within normal parameters.');

    const el = document.createElement('div');
    el.className = 'live-event-card';
    if(isTun) el.style.borderColor = 'rgba(196,75,64,.22)';
    el.onclick = ()=>{ openDrawer(encodeURIComponent(JSON.stringify(ev))); };
    el.innerHTML = `
      <div style="flex-shrink:0;width:36px;height:36px;border-radius:10px;background:${bg};display:flex;align-items:center;justify-content:center;color:${col}">
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width:16px;height:16px"><path d="${isTun?'M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z':'M22 11.08V12a10 10 0 11-5.93-9.14M22 4L12 14.01l-3-3'}"/></svg>
      </div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;flex-wrap:wrap">
          <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:${col}">${esc(level.toUpperCase())} · ${score.toFixed(1)}/100</span>
          <span style="font-size:10px;color:var(--t3);font-family:var(--mono)">${esc(ts)}</span>
          ${isTun?'<span style="font-size:10px;font-weight:700;font-family:var(--mono);background:var(--red2);color:var(--red);border-radius:999px;padding:2px 8px;border:1px solid rgba(196,75,64,.18)">TUNNEL</span>':''}
        </div>
        <div style="font-family:var(--mono);font-size:12px;font-weight:600;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(ev.query||'')}">${esc((ev.query||'unknown query').substring(0,72))}</div>
        <div style="display:flex;gap:12px;margin-top:4px;flex-wrap:wrap">
          <span style="font-size:11px;color:var(--t2)">From: <b style="color:var(--txt)">${esc(ev.src_ip||'?')}</b></span>
          <span style="font-size:11px;color:var(--t2)">Type: <b style="color:var(--txt)">${esc(ev.record_type||'?')}</b></span>
        </div>
        <div style="font-size:11px;color:var(--t3);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(reasonText)}">${esc(reasonText)}</div>
      </div>
      <div style="flex-shrink:0">
        <div class="live-score-badge ${riskCls(score)}">${score.toFixed(0)}</div>
      </div>`;
    fragment.appendChild(el);
  });

  if(empty) list.insertBefore(fragment, empty);
  else list.appendChild(fragment);
}

function clearLiveFeed() {
  fetch('/live/reset',{method:'POST'}).catch(()=>{});
  G.live = { mode:'offline', events:[], tracker:{}, stats:{total:0,high:0,medium:0,low:0,tunnel:0}, version:0, interface:'', started_at:null };
  _liveVersion = 0;
  applyLiveUpdate();
  toast('Live feed cleared');
}

// ── kpiCard builder — used by live stats row and tunnel summary cards ──────────
function kpiCard(bg, col, iconPath, val, label, sub) {
  return `<div class="kpi-card"><div class="kpi-icon" style="background:${bg};color:${col}"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="${iconPath}"/></svg></div><div class="kpi-body"><div class="kpi-val">${val}</div><div class="kpi-label">${label}</div><div class="kpi-sub">${sub}</div></div></div>`;
}

// ── Confirmed Tunnel IPs renderer ─────────────────────────────────────────────
function renderTunnelIPs(tracker, stats) {
  const grid = document.getElementById('tunnel-ip-grid');
  const summCards = document.getElementById('tunnel-summary-cards');
  if(!grid) return;

  const entries = Object.entries(tracker||{});
  const tunCount = entries.length;

  // Summary cards
  if(summCards) summCards.innerHTML =
    kpiCard('var(--red2)','var(--red)','M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z',
      tunCount, 'Confirmed Sources', `unique device${tunCount!==1?'s':''} caught`) +
    kpiCard('var(--amb2)','var(--amb)','M22 12h-4l-3 9L9 3l-3 9H2',
      fmt(entries.reduce((s,[,v])=>s+(+v.flagged_queries||0),0)), 'Suspicious Queries', 'from confirmed tunnel sources') +
    kpiCard('var(--cy2)','var(--cy)','M12 2a10 10 0 100 20A10 10 0 0012 2zM12 8v4M12 16h.01',
      tunCount?entries.reduce((mx,[,v])=>Math.max(mx,+(v.max_risk_score||0)),0).toFixed(0):'—', 'Peak Risk Score', 'out of 100');

  if(!tunCount){ show('tunnel-empty',true); grid.innerHTML=''; return; }
  show('tunnel-empty',false);

  // Sort by peak risk score descending
  const sorted = entries.slice().sort((a,b)=>(+(b[1].max_risk_score||0))-(+(a[1].max_risk_score||0)));

  grid.innerHTML = sorted.map(([ip, info]) => {
    const peakScore = +(info.max_risk_score||0);
    const flagged = +(info.flagged_queries||0);
    const samples = (info.sample_queries||[]).slice(0,3);
    const reasons = Array.isArray(info.reasons) ? info.reasons : (info.reasons ? [...info.reasons] : []);
    const firstSeen = info.first_seen ? new Date(info.first_seen).toLocaleString() : '—';
    const lastSeen  = info.last_seen  ? new Date(info.last_seen).toLocaleString()  : '—';
    const col = riskCol(peakScore), bg = riskBg(peakScore);
    const urgency = peakScore>=60 ? 'HIGH PRIORITY — Investigate immediately' : peakScore>=30 ? 'MEDIUM — Review recommended' : 'LOW — Monitor';
    const urgencyExplain = peakScore>=60
      ? 'This device was flagged with very high confidence. It is strongly recommended to isolate it from the network and investigate what data it may have exfiltrated.'
      : peakScore>=30
      ? 'This device shows suspicious DNS patterns but did not reach the highest confidence threshold. It should be reviewed.'
      : 'This device showed some unusual DNS behaviour but at a lower intensity.';

    return `<div class="tbl-wrap" style="overflow:visible;border-radius:var(--r16)">
      <!-- Header bar -->
      <div style="background:${bg};padding:16px 22px;display:flex;align-items:center;gap:16px;border-radius:var(--r16) var(--r16) 0 0">
        <div style="flex-shrink:0;width:48px;height:48px;border-radius:14px;background:var(--bg2);display:flex;align-items:center;justify-content:center;box-shadow:0 6px 18px rgba(21,34,53,.08)">
          <svg fill="none" stroke="${col}" stroke-width="2" viewBox="0 0 24 24" style="width:22px;height:22px"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        </div>
        <div style="flex:1">
          <div style="font-family:var(--mono);font-size:18px;font-weight:700;color:var(--txt)">${esc(ip)}</div>
          <div style="font-size:11px;color:var(--t2);margin-top:2px">IP Address of the device caught tunneling</div>
        </div>
        <div style="text-align:right">
          <div style="font-family:var(--syne);font-size:30px;font-weight:700;color:${col}">${peakScore.toFixed(0)}<span style="font-size:14px;font-weight:400;color:var(--t2)">/100</span></div>
          <div style="font-size:10px;font-weight:700;font-family:var(--mono);color:${col};letter-spacing:.06em">PEAK RISK SCORE</div>
        </div>
      </div>
      <!-- Body -->
      <div style="padding:20px 22px;display:flex;flex-direction:column;gap:18px">
        <!-- Urgency -->
        <div style="background:${bg};border:1px solid ${peakScore>=60?'rgba(196,75,64,.14)':'var(--bord)'};border-radius:10px;padding:12px 16px">
          <div style="font-size:11px;font-weight:700;font-family:var(--mono);color:${col};letter-spacing:.06em;margin-bottom:4px">${esc(urgency)}</div>
          <div style="font-size:12px;color:var(--t2);line-height:1.6">${esc(urgencyExplain)}</div>
        </div>
        <!-- Timeline -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
          <div class="set-card" style="padding:12px 14px;gap:4px">
            <div style="font-size:10px;font-weight:700;font-family:var(--mono);color:var(--t3);letter-spacing:.06em">FIRST DETECTED</div>
            <div style="font-size:12px;font-weight:600;color:var(--txt)">${esc(firstSeen)}</div>
          </div>
          <div class="set-card" style="padding:12px 14px;gap:4px">
            <div style="font-size:10px;font-weight:700;font-family:var(--mono);color:var(--t3);letter-spacing:.06em">LAST SEEN</div>
            <div style="font-size:12px;font-weight:600;color:var(--txt)">${esc(lastSeen)}</div>
          </div>
          <div class="set-card" style="padding:12px 14px;gap:4px">
            <div style="font-size:10px;font-weight:700;font-family:var(--mono);color:var(--t3);letter-spacing:.06em">SUSPICIOUS QUERIES</div>
            <div style="font-size:18px;font-weight:700;color:${col}">${fmt(flagged)}</div>
          </div>
        </div>
        <!-- Why flagged -->
        ${reasons.length?`<div>
          <div style="font-size:11px;font-weight:700;font-family:var(--mono);color:var(--t3);letter-spacing:.06em;margin-bottom:8px">WHY THIS DEVICE WAS FLAGGED</div>
          <div style="display:flex;flex-direction:column;gap:6px">
            ${reasons.slice(0,5).map(r=>`<div class="rule-item"><div class="rule-dot" style="background:${bg};color:${col}"><svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" style="width:10px;height:10px"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div><span>${esc(r)}</span></div>`).join('')}
          </div>
        </div>`:''}
        <!-- Sample queries -->
        ${samples.length?`<div>
          <div style="font-size:11px;font-weight:700;font-family:var(--mono);color:var(--t3);letter-spacing:.06em;margin-bottom:8px">EXAMPLE SUSPICIOUS QUERIES</div>
          <div style="display:flex;flex-direction:column;gap:4px">
            ${samples.map(q=>`<div class="subdomain-pill" style="border-radius:8px;max-width:100%;font-size:11px" title="${esc(q)}">${esc(q.substring(0,80))}</div>`).join('')}
          </div>
          <div style="font-size:11px;color:var(--t3);margin-top:6px">These look like normal website look-ups but contain hidden encoded data.</div>
        </div>`:''}
      </div>
    </div>`;
  }).join('');
}

function exportTunnelCSV() {
  const entries = Object.entries(G.live.tracker||{});
  if(!entries.length){ toast('No confirmed tunnels to export','warn'); return; }
  const header = ['ip','first_seen','last_seen','flagged_queries','max_risk_score','sample_queries','reasons'];
  const rows = entries.map(([ip,info])=>[
    ip, info.first_seen||'', info.last_seen||'',
    info.flagged_queries||0, info.max_risk_score||0,
    (info.sample_queries||[]).join(' | '),
    (info.reasons?[...info.reasons]:[]).join(' | ')
  ]);
  const csv = [header, ...rows].map(r=>r.map(v=>JSON.stringify(String(v))).join(',')).join('\n');
  const url = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  const a = document.createElement('a'); a.href=url; a.download='confirmed-tunnels.csv'; a.click();
  URL.revokeObjectURL(url);
  toast('Exported '+entries.length+' confirmed tunnel IP'+(entries.length!==1?'s':''));
}

// Also populate tunnel view from offline PCAP data when dashboard loads
function populateTunnelsFromOfflineData(rows) {
  // Build a pseudo-tracker from the offline PCAP results
  const tracker = {};
  const stats = { total:(rows||[]).length, high:0, medium:0, low:0, tunnel:0 };
  (rows||[]).forEach(r=>{
    const level = String(r.risk_level||'Low').toLowerCase();
    if(level in stats) stats[level] += 1;
    if(r.prediction==='TUNNEL') stats.tunnel += 1;
  });
  (rows||[]).filter(r=>r.prediction==='TUNNEL').forEach(r=>{
    const ip = r.src_ip||'Unknown';
    if(!tracker[ip]){
      tracker[ip] = {
        first_seen: r.ts ? new Date(r.ts*1000).toISOString() : null,
        last_seen:  r.ts ? new Date(r.ts*1000).toISOString() : null,
        flagged_queries: 0,
        max_risk_score: 0,
        sample_queries: [],
        reasons: new Set()
      };
    }
    const entry = tracker[ip];
    entry.flagged_queries++;
    entry.max_risk_score = Math.max(entry.max_risk_score, r.risk_score||0);
    if(entry.sample_queries.length<5) entry.sample_queries.push(r.query||'');
    if(r.ts){
      const d = new Date(r.ts*1000).toISOString();
      if(!entry.last_seen||d>entry.last_seen) entry.last_seen=d;
      if(!entry.first_seen||d<entry.first_seen) entry.first_seen=d;
    }
    (r.rule_reasons||[]).forEach(reason=>entry.reasons.add(reason));
  });
  // Convert Sets to arrays for rendering
  Object.values(tracker).forEach(v=>{ v.reasons=[...v.reasons]; });
  G.live = {
    ...G.live,
    mode:'offline',
    events:[],
    tracker,
    stats,
    interface:'',
    started_at:null
  };
  applyLiveUpdate();
}

// ── Init settings ─────────────────────────────────────────────────────────────
renderSettings();

// ── Keyboard ─────────────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){ e.preventDefault(); const at=document.querySelector('.ntab[data-p="alerts"]'); if(at) at.click(); setTimeout(()=>document.getElementById('qsrch')?.focus(),60); }
});
</script>
</body>
</html>"""


@app.route("/")
def index():
    page = HTML.replace("__MAX_VISIBLE_LIVE_EVENTS__", str(MAX_VISIBLE_LIVE_EVENTS))
    return Response(page, mimetype="text/html")

@app.route("/results")
def results():
    access_error = _require_local_access()
    if access_error:
        return access_error
    since = request.args.get("since", default=0, type=int)
    snapshot = _snapshot()
    if snapshot["version"] <= since:
        return jsonify({"version": snapshot["version"], "data": None})
    return jsonify(snapshot)

@app.route("/push", methods=["POST"])
def push():
    access_error = _require_local_access()
    if access_error:
        return access_error
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return _error_response("No payload", 400)

    data = payload.get("data")
    if not isinstance(data, list) or not data:
        return _error_response("Missing data", 400)
    if len(data) > MAX_PUSH_ROWS:
        return _error_response(f"Too many rows in one push (max {MAX_PUSH_ROWS})", 413)

    pcap_name = payload.get("pcap_name", "")
    try:
        normalized_rows = [_normalize_ingested_row(row) for row in data]
    except ValueError as exc:
        return _error_response(str(exc), 400)
    version = _save(
        normalized_rows,
        pcap_name,
        payload.get("thresholds"),
        payload.get("summary"),
    )
    print(f"  [push] '{pcap_name}' → v{version}")
    return jsonify({"ok": True, "version": version})

@app.route("/analyse", methods=["POST"])
def analyse():
    access_error = _require_local_access()
    if access_error:
        return access_error
    upload = request.files.get("pcap")
    if upload is None:
        return _error_response("No file", 400)
    if not upload.filename:
        return _error_response("Empty name", 400)

    temp_path = _save_uploaded_file(upload)
    try:
        result = _run_detector_pipeline(temp_path)
    except (FileNotFoundError, ValueError) as exc:
        return _error_response(str(exc), 400)
    except Exception as exc:
        return _error_response(f"Failed: {exc}", 500)
    finally:
        _remove_file(temp_path)

    version = _save(
        result["data"],
        upload.filename,
        result.get("thresholds"),
        result.get("summary"),
    )
    result.update(version=version, pcap_name=upload.filename)
    return jsonify(result)

@app.route("/live/push", methods=["POST"])
def live_push():
    """
    Called by pcap_detector.py live mode to stream scored events.

    Expected JSON body:
    {
      "event":   { ...scored_row fields... },  # required
      "tracker": { "1.2.3.4": { ... }, ... },  # optional tracker snapshot
      "interface": "eth0",                      # optional
      "window_seconds": 300                     # optional
    }

    You can also send a batch: { "events": [...], "tracker": {...} }
    """
    access_error = _require_local_access()
    if access_error:
        return access_error
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return _error_response("No payload", 400)

    try:
        tracker = _normalize_tracker_snapshot(payload.get("tracker") or {})
    except ValueError as exc:
        return _error_response(str(exc), 400)
    iface = payload.get("interface", "")
    try:
        window = _coerce_positive_int(
            payload.get("window_seconds", 300),
            300,
            "window_seconds",
        )
    except ValueError as exc:
        return _error_response(str(exc), 400)

    # Support single event or batch
    events = payload.get("events")
    if events is None:
        event = payload.get("event")
        if not event:
            return _error_response("Missing 'event' or 'events' key", 400)
        events = [event]
    elif not isinstance(events, list):
        return _error_response("'events' must be a list", 400)

    if len(events) > MAX_LIVE_BATCH:
        return _error_response(f"Too many events in one batch (max {MAX_LIVE_BATCH})", 413)

    try:
        for ev in events:
            _push_live_event(ev, tracker, iface, window)
    except ValueError as exc:
        return _error_response(str(exc), 400)

    snap = _live_snapshot()
    return jsonify({"ok": True, "version": snap["version"], "total": snap["stats"]["total"]})


@app.route("/live/status")
def live_status():
    """Return the current live-mode state and TunnelIPTracker registry."""
    access_error = _require_local_access()
    if access_error:
        return access_error
    since = request.args.get("since", default=0, type=int)
    snap = _live_snapshot(since=since)
    if snap["version"] <= since:
        return jsonify({"version": snap["version"], "new_events": None})
    return jsonify(snap)


@app.route("/live/reset", methods=["POST"])
def live_reset():
    """Clear live-mode state (e.g. start a new session)."""
    access_error = _require_local_access()
    if access_error:
        return access_error
    with _live_lock:
        _live_store.update(
            mode="offline", interface="", window_seconds=300,
            started_at=None, events=[], tracker={},
            stats={"total": 0, "high": 0, "medium": 0, "low": 0, "tunnel": 0},
            version=_live_store["version"] + 1,
        )
    return jsonify({"ok": True})


@app.errorhandler(413)
def request_too_large(_exc):
    max_mb = max(1, MAX_CONTENT_LENGTH // (1024 * 1024))
    return _error_response(f"Upload too large. Max file size is {max_mb} MB.", 413)


if __name__ == "__main__":
    host = "0.0.0.0" if ALLOW_REMOTE else "127.0.0.1"
    print(f"\n  DNSGuard dashboard -> http://{host}:8080\n")
    print("  Live push endpoint : POST http://127.0.0.1:8080/live/push")
    print("  Live status        : GET  http://127.0.0.1:8080/live/status\n")
    if not ALLOW_REMOTE:
        print("  API access is limited to localhost. Set DNS_SHIELD_ALLOW_REMOTE=1 to expose it remotely.\n")
    app.run(debug=False, host=host, port=8080)
