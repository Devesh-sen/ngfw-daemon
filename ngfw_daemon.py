#!/usr/bin/env python3
import os
import sys
import time
import socket
import json
import re
import logging
import ipaddress
import requests
import signal
import subprocess
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

# ---- Load .env (try multiple locations: /root/.env, ./ngfw.env, ./.env) ----
# Ensures daemon config is loaded regardless of where it's run
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATHS = [
    "/root/.env",                    # system-level env (root)
    os.path.join(BASE_DIR, "ngfw.env"),  # project-level env
    os.path.join(BASE_DIR, ".env")       # fallback env in project
]
for p in ENV_PATHS:
    try:
        if os.path.exists(p):
            load_dotenv(p)
            break
    except PermissionError:
        pass
else:
    load_dotenv()  # fallback to current working directory

# ---- Paths & basic config ----
# Repo-local logs/state (all relative to project dir)
LOG_DIR = os.path.join(BASE_DIR, "logs_and_utilities")         # repo-local logging dir
LOG_FILE = os.path.join(LOG_DIR, "daemon.log")                 # main daemon log
STATE_DIR = os.path.join(BASE_DIR, "logs_and_utilities")       # repo-local state dir

try:
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
except PermissionError:
    print(f"[FATAL] Permission denied creating {LOG_DIR} or {STATE_DIR}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"[FATAL] Failed to create required dirs: {e}", file=sys.stderr)
    sys.exit(1)

# ---- Persistent storage / state files (repo-local) ----
BLOCKS_DB = os.path.join(STATE_DIR, "blocked.json")            # stores currently blocked IPs
OFFSET_FILE = os.path.join(STATE_DIR, "fastlog.offset")        # tracks last read position in fast.log

# ---- Suricata system paths (do NOT modify) ----
FAST_LOG = os.getenv("FAST_LOG", "/var/log/suricata/fast.log")    # system-managed Suricata fast.log
# Suricata rules path is system-managed and specified in suricata.yaml
# e.g., /etc/suricata/rules/custom.rules

# ---- Repo-local log files ----
BLOCKS_LOG = os.getenv("BLOCKS_LOG", os.path.join(LOG_DIR, "blocks.log"))  # text log for blocked IPs
ALERT_LOG = os.path.join(LOG_DIR, "alert.log")                             # text log for alerts
ALERT_JSON = os.path.join(LOG_DIR, "alerts.json")                          # JSON log for alerts

# ---- Other configuration ----
DEFAULT_INTERVAL = 60
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", DEFAULT_INTERVAL))
HIGH_ALERT_THRESHOLD = int(os.getenv("HIGH_ALERT_THRESHOLD", "3"))
HIGH_ALERT_INTERVAL = int(os.getenv("HIGH_ALERT_INTERVAL", "5"))

# Threat intelligence / reputation thresholds
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSEIPDB_THRESHOLD = int(os.getenv("ABUSEIPDB_THRESHOLD", "70"))
RISK_THRESHOLD = int(os.getenv("RISK_THRESHOLD", str(ABUSEIPDB_THRESHOLD)))

ABUSEIPDB_TIMEOUT_S = float(os.getenv("ABUSEIPDB_TIMEOUT_S", "4.0"))
ABUSEIPDB_MAX_PER_CYCLE = int(os.getenv("ABUSEIPDB_MAX_PER_CYCLE", "20"))

# FireHOL blocklist (repo-local)
FIREHOL_FILE = os.getenv("FIREHOL_FILE", os.path.join(STATE_DIR, "firehol_level1.netset"))
FIREHOL_ENABLED = os.getenv("FIREHOL_ENABLED", "1") not in ("0", "false", "False")
FIREHOL_RELOAD_S = int(os.getenv("FIREHOL_RELOAD_S", "3600"))

# ---- Fail policy for unknown TI results ----
FAIL_POLICY = os.getenv("FAIL_POLICY", "closed").lower()
BLOCK_EXPIRE_S = int(os.getenv("BLOCK_EXPIRE_S", str(24 * 3600)))  # default 24h

# iptables binary (system-level, used to enforce blocks)
IPTABLES = "/usr/sbin/iptables" if os.path.exists("/usr/sbin/iptables") else "iptables"

# ---- Regex patterns for parsing Suricata fast.log ----
IPV4_FLOW = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s+->\s+(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")
FASTLOG_RE = re.compile(
    r"""\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+
        (?P<msg>.+?)\s+\[\*\*\].*?\{(?P<proto>[A-Z]+)\}\s+
        (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s+->\s+
        (?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?""",
    re.VERBOSE,
)

# ---- Logging setup (repo-local) ----
logger = logging.getLogger("ngfw_daemon")
logger.setLevel(logging.INFO)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
try:
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(console)
    logger.addHandler(file_handler)
except PermissionError:
    print(f"[WARN] Permission denied opening {LOG_FILE}. Logging to console only.", file=sys.stderr)
    logger.addHandler(console)
except Exception as e:
    print(f"[WARN] Failed to set up file logging: {e}. Console only.", file=sys.stderr)
    logger.addHandler(console)

# ---- Ensure repo-local log files exist ----
for path in (ALERT_LOG, ALERT_JSON, BLOCKS_LOG):
    try:
        if not os.path.exists(path):
            open(path, "w").close()
    except PermissionError:
        logger.critical(f"Permission denied creating {path}")
    except Exception as e:
        logger.error(f"Failed to prepare {path}: {e}")

# ---- Enrichment formatting ----
def _fmt_enrichment(sid=None, msg=None):
    pieces = []
    if sid is not None:
        pieces.append(f"SID={sid}")
    if msg:
        simple = " ".join(str(msg).splitlines())
        pieces.append(f'MSG="{simple}"')
    return (" " + " ".join(pieces)) if pieces else ""

# ---- log_alert writes BOTH text and JSON ----
def log_alert(ip: str, reason: str, score=None, sid=None, rule_msg=None):
    ts = datetime.now().astimezone()
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
    score_txt = f" (REPUTATION SCORE: {score})" if score is not None else ""
    enrich = _fmt_enrichment(sid, rule_msg)

    # Text log
    line = f"{ts_str} ALERT {ip}{score_txt} [{reason}]{enrich}"
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(line + "\n")
    except PermissionError:
        logger.critical(f"Permission denied writing {ALERT_LOG}")
    except FileNotFoundError:
        logger.error(f"{ALERT_LOG} not found when writing alert")
    except OSError as e:
        logger.error(f"OS error writing {ALERT_LOG}: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error writing alert.log: {e}")
    logger.info(line)

    # JSON log
    try:
        event = {
            "ts": ts.isoformat(),
            "ip": ip,
            "reason": reason,
            "score": score,
            "sid": sid,
            "msg": rule_msg,
        }
        with open(ALERT_JSON, "a") as jf:
            jf.write(json.dumps(event) + "\n")
    except PermissionError:
        logger.critical(f"Permission denied writing {ALERT_JSON}")
    except FileNotFoundError:
        logger.error(f"{ALERT_JSON} not found when writing JSON alert")
    except (TypeError, ValueError) as e:
        logger.error(f"JSON serialization error for alert: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error writing alerts.json: {e}")

# ---- Signals ----
def handle_sigterm(signum, frame):
    logger.info("Received SIGTERM, exiting.")
    sys.exit(0)

def reopen_logs(signum, frame):
    logger.info("SIGHUP received: reopening log files.")
    for h in list(logger.handlers):
        if isinstance(h, RotatingFileHandler):
            try:
                h.acquire()
                h.close()
                logger.removeHandler(h)
            finally:
                try:
                    h.release()
                except Exception:
                    pass
    try:
        new = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
        new.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        logger.addHandler(new)
        logger.info("Log files reopened.")
    except PermissionError:
        logger.critical(f"Permission denied reopening {LOG_FILE}")
    except Exception as e:
        logger.exception(f"Unexpected error reopening log file: {e}")

try:
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGHUP, reopen_logs)
except Exception as e:
    logger.warning(f"Unable to register signal handlers: {e}")

# ---- Local IPs ----
def get_local_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(res[4][0])
    except socket.gaierror as e:
        logger.debug(f"Hostname resolution error: {e}")
    except OSError as e:
        logger.debug(f"Socket error during local IP discovery: {e}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError as e:
        logger.debug(f"Outbound socket discovery failed: {e}")
    ips.add("127.0.0.1")
    return ips

LOCAL_IPS = get_local_ips()
logger.info(f"Local IPs detected: {', '.join(sorted(LOCAL_IPS))}")

def is_private_or_reserved(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any([
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_reserved,
            ip_obj.is_multicast,
        ])
    except ValueError:
        return True
    except Exception as e:
        logger.debug(f"is_private_or_reserved unexpected error for {ip_str}: {e}")
        return True

# ---- file helpers ----
def ensure_file(path):
    try:
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(f"=== {os.path.basename(path)} started ===\n")
            os.chmod(path, 0o600)
    except PermissionError:
        logger.critical(f"Permission denied preparing {path}")
    except FileNotFoundError:
        logger.error(f"Path not found preparing {path}")
    except OSError as e:
        logger.error(f"OS error preparing {path}: {e}")
    except Exception as e:
        logger.exception(f"Could not prepare {path}: {e}")

ensure_file(BLOCKS_LOG)
ensure_file(ALERT_LOG)

def log_block(ip: str, reason: str, score=None, sid=None, rule_msg=None):
    ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    score_txt = f" (REPUTATION SCORE: {score})" if score is not None else ""
    enrich = _fmt_enrichment(sid, rule_msg)
    line = f"{ts} BLOCKED {ip}{score_txt} [{reason}]{enrich}"
    try:
        with open(BLOCKS_LOG, "a") as f:
            f.write(line + "\n")
    except PermissionError:
        logger.critical(f"Permission denied writing {BLOCKS_LOG}")
    except FileNotFoundError:
        logger.error(f"{BLOCKS_LOG} not found when writing block")
    except OSError as e:
        logger.error(f"OS error writing {BLOCKS_LOG}: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error writing blocks.log: {e}")
    logger.warning(line)

# ---- iptables helpers ----
def is_blocked(ip: str, chain: str = "INPUT") -> bool:
    try:
        return subprocess.run(
            [IPTABLES, "-C", chain, "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except FileNotFoundError:
        logger.critical("iptables binary not found while checking rule")
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking iptables for {ip}: {e}")
        return False

def add_iptables_drop(ip: str, chain: str = "INPUT") -> bool:
    if is_blocked(ip, chain):
        return False
    try:
        subprocess.run([IPTABLES, "-I", chain, "1", "-s", ip, "-j", "DROP"], check=True)
        return True
    except FileNotFoundError:
        logger.critical("iptables binary not found — cannot enforce blocks!")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"iptables failed inserting rule for {ip}: {e}")
        return False
    except PermissionError:
        logger.critical("Permission denied executing iptables. Missing CAP_NET_ADMIN?")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error adding iptables rule for {ip}: {e}")
        return False

def remove_iptables_drop(ip: str, chain: str = "INPUT") -> bool:
    try:
        while subprocess.run(
            [IPTABLES, "-C", chain, "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0:
            subprocess.run([IPTABLES, "-D", chain, "-s", ip, "-j", "DROP"], check=True)
        return True
    except FileNotFoundError:
        logger.critical("iptables binary not found — cannot remove rules!")
        return False
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to remove iptables rule for {ip}: {e}")
        return False
    except PermissionError:
        logger.critical("Permission denied executing iptables delete. Missing CAP_NET_ADMIN?")
        return False
    except Exception as e:
        logger.exception(f"Unexpected error removing iptables rule for {ip}: {e}")
        return False

# ---- persistent block store ----
_blocks = {}  # ip -> {"ts": iso, "reason": str, "score": int|None, "sid": int|None, "msg": str|None}

def load_blocks():
    global _blocks
    try:
        if os.path.exists(BLOCKS_DB) and os.path.getsize(BLOCKS_DB) > 0:
            with open(BLOCKS_DB, "r") as f:
                _blocks = json.load(f)
        else:
            _blocks = {}
    except json.JSONDecodeError as e:
        logger.error(f"Corrupted JSON in {BLOCKS_DB}: {e}")
        _blocks = {}
    except PermissionError:
        logger.critical(f"Permission denied reading {BLOCKS_DB}")
        _blocks = {}
    except FileNotFoundError:
        logger.warning(f"{BLOCKS_DB} not found; starting with empty block DB.")
        _blocks = {}
    except OSError as e:
        logger.error(f"OS error reading {BLOCKS_DB}: {e}")
        _blocks = {}
    except Exception as e:
        logger.exception(f"Unexpected error loading {BLOCKS_DB}: {e}")
        _blocks = {}

def save_blocks():
    try:
        with open(BLOCKS_DB, "w") as f:
            json.dump(_blocks, f)
    except PermissionError:
        logger.critical(f"Permission denied writing {BLOCKS_DB}")
    except FileNotFoundError:
        logger.error(f"{BLOCKS_DB} path not found when saving blocks DB")
    except (TypeError, ValueError) as e:
        logger.error(f"JSON serialization error saving blocks DB: {e}")
    except OSError as e:
        logger.error(f"OS error writing {BLOCKS_DB}: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error persisting blocks DB: {e}")

def record_block(ip, reason, score=None, sid=None, rule_msg=None):
    ts = datetime.now(timezone.utc).isoformat()
    _blocks[ip] = {"ts": ts, "reason": reason, "score": score, "sid": sid, "msg": rule_msg}
    save_blocks()
    log_block(ip, reason, score, sid, rule_msg)
    log_alert(ip, reason, score, sid, rule_msg)

def prune_expired_blocks():
    now = datetime.now(timezone.utc)
    removed = []
    for ip, meta in list(_blocks.items()):
        try:
            ts = datetime.fromisoformat(meta["ts"])
        except (KeyError, ValueError) as e:
            logger.debug(f"Malformed entry in blocks DB for {ip}: {e}")
            _blocks.pop(ip, None)
            continue
        except Exception as e:
            logger.debug(f"Unexpected parse error for block entry {ip}: {e}")
            continue

        try:
            if (now - ts).total_seconds() > BLOCK_EXPIRE_S:
                if remove_iptables_drop(ip):
                    removed.append(ip)
                _blocks.pop(ip, None)
        except Exception as e:
            logger.debug(f"Error during expiry check/removal for {ip}: {e}")
            continue
    if removed:
        save_blocks()
        logger.info(f"Unblocked expired IPs: {', '.join(removed)}")

# ---- fast.log incremental reader with SID/MSG ----
def _read_offset():
    try:
        if os.path.exists(OFFSET_FILE):
            with open(OFFSET_FILE, "r") as f:
                return int((f.read() or "0").strip())
    except ValueError:
        logger.debug(f"Offset file {OFFSET_FILE} contains invalid integer; resetting to 0")
    except PermissionError:
        logger.critical(f"Permission denied reading {OFFSET_FILE}")
    except Exception as e:
        logger.debug(f"Unexpected error reading offset: {e}")
    return 0

def _write_offset(offset):
    try:
        with open(OFFSET_FILE, "w") as f:
            f.write(str(offset))
    except PermissionError:
        logger.critical(f"Permission denied writing {OFFSET_FILE}")
    except OSError as e:
        logger.error(f"OS error writing {OFFSET_FILE}: {e}")
    except Exception as e:
        logger.exception(f"Failed to write offset file: {e}")

def extract_events_from_fastlog(include_private: bool = False):
    """
    Read new fast.log lines since saved offset and return deduped event list:
    [{'ip': '1.2.3.4', 'sid': 1000001 | None, 'msg': '...'}, ...]
    """
    events = []
    if not os.path.exists(FAST_LOG):
        logger.debug(f"FAST_LOG {FAST_LOG} not present; skipping.")
        return events

    offset = _read_offset()
    try:
        with open(FAST_LOG, "r", errors="ignore") as f:
            file_size = os.path.getsize(FAST_LOG)
            if offset > file_size:
                logger.info("fast.log rotated/truncated; resetting offset to 0")
                offset = 0
            f.seek(offset)
            lines = f.readlines()
            _write_offset(f.tell())
    except FileNotFoundError:
        logger.warning(f"{FAST_LOG} missing during read")
        return events
    except PermissionError:
        logger.critical(f"Permission denied reading {FAST_LOG}")
        return events
    except OSError as e:
        logger.error(f"OS error reading fast.log: {e}")
        return events
    except Exception as e:
        logger.exception(f"Unexpected error reading fast.log: {e}")
        return events

    # parse lines -> create raw events
    raw = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        sid = None
        msg = None
        src_ip = None

        try:
            m = FASTLOG_RE.search(line)
            if m:
                try:
                    sid = int(m.group("sid"))
                except (TypeError, ValueError):
                    sid = None
                msg = m.group("msg").strip() if m.group("msg") else None
                src_ip = m.group("src_ip")
            else:
                m2 = IPV4_FLOW.search(line)
                if m2:
                    src_ip = m2.group(1)
        except re.error as e:
            logger.debug(f"Regex parse error on fast.log line: {e}")
            continue

        if not src_ip:
            continue

        try:
            ip_obj = ipaddress.IPv4Address(src_ip)
        except ValueError:
            logger.debug(f"Skipping malformed IP in fast.log: {src_ip}")
            continue
        except Exception as e:
            logger.debug(f"Unexpected IP parse error for '{src_ip}': {e}")
            continue

        if not include_private and (ip_obj.is_private or ip_obj.is_loopback):
            continue

        raw.append({"ip": str(ip_obj), "sid": sid, "msg": msg})

    # dedupe/aggregate per-ip so a single decision is made per IP per cycle
    events_by_ip = {}
    for r in raw:
        ip = r["ip"]
        if ip not in events_by_ip:
            events_by_ip[ip] = {"ip": ip, "sids": [], "msgs": []}
        if r.get("sid") is not None:
            events_by_ip[ip]["sids"].append(r["sid"])
        if r.get("msg"):
            events_by_ip[ip]["msgs"].append(r["msg"])

    for ip, v in events_by_ip.items():
        sid_val = v["sids"][0] if v["sids"] else None
        msg_val = "; ".join(v["msgs"]) if v["msgs"] else None
        events.append({"ip": ip, "sid": sid_val, "msg": msg_val})

    return events

# ---- AbuseIPDB + FireHOL ----
_abuse_cache = {}
ABUSE_TTL = int(os.getenv("ABUSEIPDB_CACHE_TTL_S", "1800"))

def check_abuseipdb(ip: str, allow_query: bool = True):
    """
    Returns (verdict, score, source_tag)
    source_tag = 'abuseipdb(cache)', 'abuseipdb' (live), 'abuseipdb(nolookup)' when not allowed to query,
    or ('unknown', None, 'abuseipdb') if error/no-key.
    """
    now = datetime.now(timezone.utc)
    if ip in _abuse_cache:
        verdict, score, ts = _abuse_cache[ip]
        if (now - ts).total_seconds() < ABUSE_TTL:
            return verdict, score, "abuseipdb(cache)"

    if not ABUSEIPDB_API_KEY or not allow_query:
        return "unknown", None, "abuseipdb(nolookup)"

    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        r = requests.get(url, headers=headers, timeout=ABUSEIPDB_TIMEOUT_S)
        r.raise_for_status()  # granular handling
        data = r.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        verdict = "block" if score >= ABUSEIPDB_THRESHOLD else "clean"
    except requests.Timeout:
        logger.warning(f"AbuseIPDB timeout for {ip}")
        verdict, score = "unknown", None
    except requests.ConnectionError:
        logger.error(f"AbuseIPDB connection error for {ip}")
        verdict, score = "unknown", None
    except requests.HTTPError as e:
        status = e.response.status_code if e.response else "unknown"
        logger.error(f"AbuseIPDB HTTP {status} for {ip}")
        verdict, score = "unknown", None
    except ValueError:
        logger.error(f"Invalid JSON from AbuseIPDB for {ip}")
        verdict, score = "unknown", None
    except Exception as e:
        logger.exception(f"Unexpected AbuseIPDB error for {ip}: {e}")
        verdict, score = "unknown", None

    _abuse_cache[ip] = (verdict, score, now)
    return verdict, score, "abuseipdb"

_firehol = set()
_firehol_loaded_at = None

def _load_firehol():
    global _firehol, _firehol_loaded_at
    if not FIREHOL_ENABLED:
        return
    try:
        with open(FIREHOL_FILE, "r") as f:
            entries = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        _firehol = set(entries)
        _firehol_loaded_at = datetime.now(timezone.utc)
        logger.info(f"FireHOL loaded: {len(_firehol)} entries")
    except FileNotFoundError:
        logger.error(f"FireHOL file not found: {FIREHOL_FILE}")
    except PermissionError:
        logger.critical(f"Permission denied reading FireHOL file: {FIREHOL_FILE}")
    except OSError as e:
        logger.error(f"OS error loading FireHOL: {e}")
    except Exception as e:
        logger.exception(f"Could not load FireHOL list: {e}")

def _need_reload_firehol():
    if not FIREHOL_ENABLED:
        return False
    if _firehol_loaded_at is None:
        return True
    try:
        return (datetime.now(timezone.utc) - _firehol_loaded_at).total_seconds() > FIREHOL_RELOAD_S
    except Exception:
        return True

def check_firehol(ip: str):
    if not FIREHOL_ENABLED:
        return "unknown", None, "firehol"
    if _need_reload_firehol():
        _load_firehol()
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        for item in _firehol:
            try:
                if "/" in item:
                    if ip_obj in ipaddress.IPv4Network(item, strict=False):
                        return "block", None, "firehol"
                else:
                    if ip == item:
                        return "block", None, "firehol"
            except ValueError:
                continue
            except Exception:
                continue
        return "clean", None, "firehol"
    except ValueError:
        return "unknown", None, "firehol"
    except Exception as e:
        logger.debug(f"Unexpected FireHOL check error for {ip}: {e}")
        return "unknown", None, "firehol"

# ---- Consolidated reputation evaluation helper ----
def evaluate_reputation_and_decide(ip: str, sid=None, rule_msg=None, allow_abuse_query=True):
    sources = {}
    a_verdict, a_score, a_tag = check_abuseipdb(ip, allow_query=allow_abuse_query)
    sources["abuseipdb"] = (a_verdict, a_score, a_tag)

    f_verdict, f_score, f_tag = check_firehol(ip)
    sources["firehol"] = (f_verdict, f_score, f_tag)

    score = a_score if a_score is not None else None

    if f_verdict == "block":
        reason = f"REPUTATION BLOCK (source=firehol)"
        return "block", score, reason, sources

    if a_score is not None and a_score >= RISK_THRESHOLD:
        reason = f"REPUTATION BLOCK (source=abuseipdb,score={a_score})"
        return "block", score, reason, sources

    providers_total = 1 + (1 if FIREHOL_ENABLED else 0)
    unknown_count = 0
    provider_positive = False
    for p, (v, s, t) in sources.items():
        if v == "unknown":
            unknown_count += 1
        elif v == "clean":
            provider_positive = True
        elif v == "block":
            provider_positive = True
        if s is not None and s < RISK_THRESHOLD:
            provider_positive = True

    if unknown_count == providers_total:
        if FAIL_POLICY == "closed":
            reason = "REPUTATION UNKNOWN (fail-closed: all TI providers failed)"
            return "block", score, reason, sources
        else:
            reason = "REPUTATION UNKNOWN (fail-open: all TI providers failed)"
            return "allow", score, reason, sources

    reason_parts = []
    if a_score is not None:
        reason_parts.append(f"abuseipdb(score={a_score})")
    else:
        reason_parts.append(f"abuseipdb({sources['abuseipdb'][0]})")
    if FIREHOL_ENABLED:
        reason_parts.append(f"firehol({sources['firehol'][0]})")
    reason = "REPUTATION CLEAN (" + ",".join(reason_parts) + ")"
    return "allow", score, reason, sources

# ---- Main loop ----
def main():
    ensure_file(BLOCKS_LOG)
    ensure_file(ALERT_LOG)
    load_blocks()

    logger.info("NGFW daemon starting up...")
    logger.info(f"Poll interval={POLL_INTERVAL}s, High alert threshold={HIGH_ALERT_THRESHOLD}, block expiry={BLOCK_EXPIRE_S}s")
    logger.info(f"Risk threshold={RISK_THRESHOLD}, AbuseIPDB threshold={ABUSEIPDB_THRESHOLD}, Fail policy={FAIL_POLICY}")

    # Quick sanity: iptables availability (non-fatal)
    try:
        subprocess.run([IPTABLES, "-L"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except FileNotFoundError:
        logger.critical("iptables not found. Blocking will not work.")
    except Exception as e:
        logger.debug(f"iptables preflight error (non-fatal): {e}")

    high_alert = False

    while True:
        try:
            prune_expired_blocks()
            logger.debug("Reading fast.log incrementally...")
            events = extract_events_from_fastlog(include_private=True)

            if not events:
                logger.debug("No new events found.")
            else:
                abuse_queries = 0
                blocked_this_cycle = 0

                for ev in events:
                    try:
                        ip = ev["ip"]
                        sid = ev.get("sid")
                        rule_msg = ev.get("msg")

                        #if ip in LOCAL_IPS or is_private_or_reserved(ip):
                            #logger.debug(f"Skipping internal/reserved IP {ip}")
                            #log_alert(ip, reason="INTERNAL/PRIVATE (skipped)", sid=sid, rule_msg=rule_msg)
                            #continue

                        allow_query = abuse_queries < ABUSEIPDB_MAX_PER_CYCLE
                        decision, score, reason, sources = evaluate_reputation_and_decide(
                            ip, sid=sid, rule_msg=rule_msg, allow_abuse_query=allow_query
                        )

                        a_tag = sources.get("abuseipdb", (None, None, None))[2]
                        if a_tag == "abuseipdb":
                            abuse_queries += 1

                        if decision == "block":
                            if add_iptables_drop(ip):
                                record_block(ip, reason=reason, score=score, sid=sid, rule_msg=rule_msg)
                                blocked_this_cycle += 1
                            else:
                                log_alert(ip, reason=f"{reason} (already-blocked?)", score=score, sid=sid, rule_msg=rule_msg)
                        else:
                            log_alert(ip, reason=reason, score=score, sid=sid, rule_msg=rule_msg)
                    except KeyError as e:
                        logger.debug(f"Event missing expected key {e}; skipping event: {ev}")
                        continue
                    except Exception as e:
                        logger.exception(f"Unexpected error processing event {ev}: {e}")
                        continue

                if blocked_this_cycle >= HIGH_ALERT_THRESHOLD:
                    if not high_alert:
                        logger.warning(f"High-Alert Mode activated! Interval={HIGH_ALERT_INTERVAL}s")
                    high_alert = True
                elif high_alert and blocked_this_cycle == 0:
                    logger.info(f"Returning to normal polling ({POLL_INTERVAL}s)")
                    high_alert = False

            time.sleep(HIGH_ALERT_INTERVAL if high_alert else POLL_INTERVAL)

        except KeyboardInterrupt:
            logger.info("Shutdown requested (KeyboardInterrupt).")
            break
        except Exception as e:
            logger.exception(f"Main loop unexpected error: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutdown (KeyboardInterrupt).")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)

