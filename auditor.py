#!/usr/bin/env python3
"""
ssh-tls-auditor — SSH and TLS misconfiguration auditor

Checks one or more target servers for:
  - Open ports (22, 80, 443)
  - SSH algorithms (key exchange, ciphers, MACs)
  - SSH banner / server version
  - SSH root login status
  - SSH password authentication
  - SSH legacy hardware detection (HP iLO, Cisco, Dropbear, etc.)
  - TLS version support (1.0, 1.1, 1.2, 1.3)
  - TLS certificate (trust, expiry, hostname match)
  - HTTP → HTTPS redirect and HSTS header

Usage:
    python3 auditor.py <target> [<target> ...]
    python3 auditor.py -f hosts.txt
    python3 auditor.py example.com 192.168.1.10 --csv report.csv
    python3 auditor.py example.com --html report.html
    python3 auditor.py example.com --json report.json
    python3 auditor.py -f hosts.txt --parallel --timeout 10
    python3 auditor.py example.com --only ssh tls
    python3 auditor.py example.com --quiet
    python3 auditor.py example.com --config
"""

import argparse
import concurrent.futures
import csv
import datetime
import html as html_module
import http.client
import io
import ipaddress
import json
import socket
import ssl
import sys
import threading
import warnings

import dns.resolver
import paramiko
import paramiko.message


# ── Thread-local stdout ────────────────────────────────────────────────────────
#
# contextlib.redirect_stdout modifies sys.stdout globally and is not
# thread-safe. Instead we install a single dispatcher as sys.stdout at import
# time. When a thread sets _thread_local.output to a StringIO buffer, all
# print() calls from that thread go to the buffer. Other threads (including
# the main thread) keep writing to the real stdout unchanged.

class _ThreadLocalStdout:
    def __init__(self, real: io.TextIOWrapper) -> None:
        self._real = real

    def write(self, s: str) -> int:
        buf = getattr(_thread_local, "output", None)
        return (buf if buf is not None else self._real).write(s)

    def flush(self) -> None:
        buf = getattr(_thread_local, "output", None)
        (buf if buf is not None else self._real).flush()

    def fileno(self) -> int:
        return self._real.fileno()

    def isatty(self) -> bool:
        return self._real.isatty()


# ── Module-level configuration ─────────────────────────────────────────────────

_timeout: int = 5
_quiet:   bool = False
_config:  bool = False
CHECK_GROUPS = ("ports", "ssh", "tls", "http")

# Best-practice algorithm lists used by the config generator.
_SSH_BEST_KEX     = "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
_SSH_BEST_CIPHERS = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
_SSH_BEST_MACS    = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"

# ANSI colour codes — only used when stdout is a real TTY
_ANSI_GREEN  = "\033[32m"
_ANSI_RED    = "\033[31m"
_ANSI_YELLOW = "\033[33m"
_ANSI_BLUE   = "\033[34m"
_ANSI_RESET  = "\033[0m"

# Grade thresholds: (min_criticals, grade)
_GRADE_THRESHOLDS = [(0, "A"), (1, "B"), (2, "C"), (4, "D"), (float("inf"), "F")]
_GRADE_COLOURS = {"A": _ANSI_GREEN, "B": _ANSI_GREEN, "C": _ANSI_YELLOW,
                  "D": _ANSI_YELLOW, "F": _ANSI_RED}
_BADGE_COLOURS = {"A": "brightgreen", "B": "green", "C": "yellow",
                  "D": "orange",      "F": "red"}


def _colourise(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{_ANSI_RESET}"
    return text


# ── Thread-local result tracking ───────────────────────────────────────────────

_thread_local = threading.local()

# Install the thread-local stdout dispatcher now that _thread_local exists.
sys.stdout = _ThreadLocalStdout(sys.stdout)  # type: ignore[assignment]

# Serialises the KEXINIT monkey-patch in check_ssh_algorithms and
# check_ssh_legacy so parallel threads do not overwrite each other's patch.
_kex_patch_lock = threading.Lock()


def _host() -> str:
    return getattr(_thread_local, "host", "")


def _category() -> str:
    return getattr(_thread_local, "category", "")


def _counts() -> dict[str, int]:
    if not hasattr(_thread_local, "counts"):
        _thread_local.counts = {"pass": 0, "fail": 0}
    return _thread_local.counts


def _reset_counts() -> None:
    _thread_local.counts = {"pass": 0, "fail": 0}


_results: list[dict] = []
_results_lock = threading.Lock()


# ── Result helpers ─────────────────────────────────────────────────────────────

def _record(result: str, label: str, detail: str,
            remediation: str = "", severity: str = "") -> None:
    with _results_lock:
        _results.append({
            "host":        _host(),
            "category":    _category(),
            "check":       label,
            "result":      result,
            "detail":      detail,
            "remediation": remediation,
            "severity":    severity,
        })


def passed(label: str, detail: str = "") -> None:
    _counts()["pass"] += 1
    _record("PASS", label, detail)
    if _quiet:
        return
    tag  = _colourise("[PASS]", _ANSI_GREEN)
    line = f"  {tag}  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def failed(label: str, detail: str = "", remediation: str = "",
           severity: str = "WARNING") -> None:
    _counts()["fail"] += 1
    _record("FAIL", label, detail, remediation, severity)
    if severity == "CRITICAL":
        tag = _colourise("[CRIT]", _ANSI_RED)
    else:
        tag = _colourise("[WARN]", _ANSI_YELLOW)
    line = f"  {tag}  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def info(label: str, detail: str = "") -> None:
    _record("INFO", label, detail)
    if _quiet:
        return
    tag  = _colourise("[INFO]", _ANSI_BLUE)
    line = f"  {tag}  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


# ── Legacy device fingerprint database ─────────────────────────────────────────
#
# Each entry describes one class of device or implementation. Matching is done
# in two ways:
#
#   Banner match   — any banner_hint substring found (case-insensitive) in the
#                    SSH version string. High confidence.
#
#   Algorithm fingerprint — at least one kex_indicator is present in the server's
#                    advertised KEX list, AND none of the kex_modern_absent algos
#                    are present (to avoid false positives on servers that support
#                    both legacy and modern algorithms), AND at least one
#                    cipher_indicator is present (if the set is non-empty).
#                    Medium confidence.
#
# insecure_kex / insecure_ciphers — subsets of algorithms from this device that
# should be flagged as [FAIL] when present and have no modern counterpart in the
# same category.

_LEGACY_FINGERPRINTS: list[dict] = [
    # ── Banner-matched (high confidence) ───────────────────────────────────────
    {
        "name":              "Dropbear SSH",
        "banner_hints":      ["dropbear"],
        "kex_indicators":    set(),
        "kex_modern_absent": set(),
        "cipher_indicators": set(),
        "note": (
            "Lightweight SSH daemon common in embedded devices (routers, NAS, IoT). "
            "Verify firmware is current and check vendor security advisories."
        ),
        "insecure_kex":     set(),
        "insecure_ciphers": set(),
    },
    {
        "name":              "Cisco IOS / IOS-XE",
        "banner_hints":      ["cisco"],
        "kex_indicators":    {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"},
        "kex_modern_absent": {"curve25519-sha256", "ecdh-sha2-nistp256"},
        "cipher_indicators": set(),
        "note": (
            "Enable SSHv2 with modern crypto: 'ip ssh version 2'. "
            "Refer to the Cisco SSH hardening guide and upgrade IOS."
        ),
        "insecure_kex":     {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"},
        "insecure_ciphers": {"3des-cbc", "aes128-cbc", "aes256-cbc"},
    },
    {
        "name":              "Fortinet FortiGate",
        "banner_hints":      ["fgssh", "fortissh", "fortigate"],
        "kex_indicators":    set(),
        "kex_modern_absent": set(),
        "cipher_indicators": set(),
        "note": (
            "Fortinet appliance — ensure FortiOS is current and SSH crypto "
            "is hardened under System > Config > SSH."
        ),
        "insecure_kex":     set(),
        "insecure_ciphers": set(),
    },
    {
        "name":              "Juniper JunOS",
        "banner_hints":      ["jnpr", "junos"],
        "kex_indicators":    set(),
        "kex_modern_absent": set(),
        "cipher_indicators": set(),
        "note": (
            "Juniper appliance — verify Junos SSH configuration and "
            "apply current security advisories."
        ),
        "insecure_kex":     set(),
        "insecure_ciphers": set(),
    },
    # ── Algorithm-fingerprinted (medium confidence) ────────────────────────────
    {
        "name": "HP iLO 2 / iLO 3 or similar legacy BMC",
        # iLO uses a generic OpenSSH banner — no banner hint available.
        # Identified by: only SHA-1 KEX, CBC ciphers, no ECDH or curve25519.
        "banner_hints":      [],
        "kex_indicators":    {"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"},
        "kex_modern_absent": {
            "curve25519-sha256", "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
        },
        "cipher_indicators": {"aes128-cbc", "3des-cbc"},
        "note": (
            "Likely a legacy BMC or embedded management interface (HP iLO 2/3, "
            "Dell iDRAC, or similar). Upgrade firmware to the latest supported version. "
            "If SSH remains unusable, use HTTPS/RIBCL for remote management."
        ),
        "insecure_kex":     {"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"},
        "insecure_ciphers": {"aes128-cbc", "aes256-cbc", "3des-cbc"},
    },
    {
        "name": "Generic legacy embedded firmware",
        # Catch-all: only group1-sha1 KEX, no modern KEX at all.
        "banner_hints":      [],
        "kex_indicators":    {"diffie-hellman-group1-sha1"},
        "kex_modern_absent": {
            "curve25519-sha256", "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
            "diffie-hellman-group14-sha1",  # even this is absent — truly minimal
        },
        "cipher_indicators": set(),
        "note": (
            "Only group1-sha1 KEX with no modern alternatives — likely very old "
            "embedded firmware or an EOL network appliance. Replace or isolate."
        ),
        "insecure_kex":     {"diffie-hellman-group1-sha1"},
        "insecure_ciphers": set(),
    },
]

# Sets used for the "no modern alternative" FAIL check, independent of any
# specific device fingerprint.
_MODERN_KEX = {
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
}
_LEGACY_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}
_LEGACY_CIPHERS = {
    "arcfour", "arcfour128", "arcfour256",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
}


def _match_fingerprint(
    banner: str, kex: list[str], ciphers: list[str]
) -> tuple[dict | None, str]:
    """Return the best-matching fingerprint and how it was matched.

    Returns:
        (fingerprint_dict, match_method) where match_method is
        "banner" or "fingerprint", or (None, "") if no match.
    """
    kex_set    = set(kex)
    cipher_set = set(ciphers)
    banner_lc  = banner.lower()

    for fp in _LEGACY_FINGERPRINTS:
        # ── Banner match ───────────────────────────────────────────────────────
        if fp["banner_hints"] and any(h in banner_lc for h in fp["banner_hints"]):
            return fp, "banner"

        # ── Algorithm fingerprint ──────────────────────────────────────────────
        if not fp["kex_indicators"]:
            continue  # needs a banner hint — skip

        kex_hit     = bool(fp["kex_indicators"] & kex_set)
        modern_gone = not bool(fp["kex_modern_absent"] & kex_set)
        cipher_hit  = (not fp["cipher_indicators"]) or bool(fp["cipher_indicators"] & cipher_set)

        if kex_hit and modern_gone and cipher_hit:
            return fp, "fingerprint"

    return None, ""


# ── SSH KEXINIT capture helper ──────────────────────────────────────────────────

def _capture_kexinit(target: str) -> tuple[dict, str]:
    """Open an SSH connection, capture the server's KEXINIT algorithm lists and
    the version banner, then close the connection.

    Uses _kex_patch_lock to serialise the Transport._parse_kex_init monkey-patch
    so that parallel scans do not overwrite each other's patched method.

    Returns:
        (captured, banner) where captured is a dict with keys kex/ciphers/macs,
        or ({}, "") on connection failure.
    """
    captured: dict[str, list] = {}
    banner   = ""

    original = paramiko.Transport._parse_kex_init

    def capturing(self, m):
        copy = paramiko.message.Message(m.asbytes())
        copy.get_bytes(16)
        captured["kex"]     = copy.get_list()
        copy.get_list()
        captured["ciphers"] = copy.get_list()
        copy.get_list()
        captured["macs"]    = copy.get_list()
        original(self, m)

    transport = None
    with _kex_patch_lock:
        paramiko.Transport._parse_kex_init = capturing
        try:
            transport = paramiko.Transport((target, 22))
            transport.start_client(timeout=_timeout)
            banner = transport.remote_version or ""
        except Exception:
            pass
        finally:
            paramiko.Transport._parse_kex_init = original

    if transport:
        transport.close()

    return captured, banner


# ── Checks ─────────────────────────────────────────────────────────────────────

def check_open_ports(target: str) -> None:
    """Check whether ports 22, 80, and 443 are open on the target."""
    _thread_local.category = "Port Check"
    print("\n[Port Check]")

    ports = {22: "SSH", 80: "HTTP", 443: "HTTPS"}
    remediations = {
        22:  "Ensure sshd is running: sudo systemctl start sshd",
        80:  "Start your web server and open port 80 in the firewall.",
        443: "Configure TLS on your web server and open port 443 in the firewall.",
    }
    for port, label in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                passed(f"Port {port} ({label})", "open")
            else:
                failed(f"Port {port} ({label})", "closed", remediations[port])
        except socket.gaierror:
            failed(f"Port {port} ({label})", "could not resolve host")
        except socket.timeout:
            failed(f"Port {port} ({label})", "timed out")


def check_ssh_algorithms(target: str) -> None:
    """Connect to SSH and enumerate accepted key exchange, cipher, and MAC algorithms.

    Captures the server's KEXINIT message via _capture_kexinit(). The KEXINIT
    lists every algorithm the server supports, not just the one that gets
    negotiated. Each algorithm is checked against known weak sets and reported
    as [PASS] or [FAIL].
    """
    _thread_local.category = "SSH Algorithms"
    print("\n[SSH Algorithms]")

    WEAK_KEX = {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
    }
    WEAK_CIPHERS = {
        "arcfour", "arcfour128", "arcfour256",
        "3des-cbc", "blowfish-cbc", "cast128-cbc",
        "aes128-cbc", "aes192-cbc", "aes256-cbc",
    }
    WEAK_MACS = {
        "hmac-md5", "hmac-md5-96",
        "hmac-sha1", "hmac-sha1-96",
        "umac-64@openssh.com",
    }

    captured, _ = _capture_kexinit(target)

    if not captured:
        failed("Could not retrieve algorithm list from server")
        return

    def evaluate(label: str, algos: list, weak_set: set, config_key: str) -> None:
        print(f"  {label}:")
        for algo in algos:
            if algo in weak_set:
                failed(
                    algo,
                    "deprecated",
                    f"Remove '{algo}' from {config_key} in sshd_config and reload sshd.",
                )
            else:
                passed(algo)

    evaluate("Key exchange", captured.get("kex", []),     WEAK_KEX,     "KexAlgorithms")
    evaluate("Ciphers",      captured.get("ciphers", []), WEAK_CIPHERS, "Ciphers")
    evaluate("MACs",         captured.get("macs", []),    WEAK_MACS,    "MACs")


def check_ssh_banner(target: str) -> None:
    """Read the SSH server banner and check the OpenSSH version.

    The server version string (e.g. SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.1)
    is sent in cleartext before authentication. It is always shown as [INFO]
    so the user has context regardless of the outcome.

    For OpenSSH, the version number is parsed and compared against a minimum:
      < 8.0 — [FAIL]: pre-2019 release, likely missing security fixes
      >= 8.0 — [PASS]: current enough for most environments

    Note: Linux distros sometimes backport security patches without bumping
    the upstream version number. Treat a low version as a prompt to verify,
    not a definitive verdict.

    Non-OpenSSH implementations (Dropbear, custom banners) are shown as [INFO]
    only — no version threshold is applied since their release cycles differ.
    """
    _thread_local.category = "SSH Banner"
    print("\n[SSH Banner]")

    _, banner = _capture_kexinit(target)

    if not banner:
        info("SSH server version", "no banner received")
        return

    info("SSH server version", banner)

    if "OpenSSH_" not in banner:
        return

    try:
        raw     = banner.split("OpenSSH_")[1].split()[0]   # "9.2p1"
        numeric = raw.split("p")[0]                         # "9.2"
        major   = int(numeric.split(".")[0])
    except (IndexError, ValueError):
        info("OpenSSH version", "could not parse version number")
        return

    if major < 8:
        failed(
            "OpenSSH version",
            f"{raw} — outdated (< 8.0), upgrade recommended",
            "Upgrade OpenSSH: sudo apt upgrade openssh-server  or  sudo dnf upgrade openssh-server",
        )
    else:
        passed("OpenSSH version", f"{raw} — current")


def check_ssh_host_keys(target: str) -> None:
    """Check the SSH host key types and sizes advertised by the server.

    Connects to port 22 and reads the server's host key via paramiko.
    Checks:
      - RSA keys with < 3072 bits are flagged as [FAIL] (NIST recommends 3072+)
      - DSA keys are always [FAIL] — fixed 1024-bit, broken
      - ECDSA keys are [PASS] (256/384/521-bit curves)
      - ED25519 keys are [PASS] — recommended
    """
    _thread_local.category = "SSH Host Keys"
    print("\n[SSH Host Keys]")

    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=_timeout)
        host_key = transport.get_remote_server_key()

        key_type = host_key.get_name()
        bits = host_key.get_bits() if hasattr(host_key, "get_bits") else None

        if key_type == "ssh-dss":
            failed(
                "Host key type",
                "DSA — broken (fixed 1024-bit, deprecated since OpenSSH 7.0)",
                "Replace DSA host key with ED25519: ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key",
                severity="CRITICAL",
            )
        elif key_type == "ssh-rsa":
            if bits is not None and bits < 3072:
                failed(
                    "Host key type",
                    f"RSA {bits}-bit — below recommended minimum of 3072 bits",
                    "Regenerate with a larger key: ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key  or switch to ED25519.",
                )
            else:
                size_str = f"RSA {bits}-bit" if bits else "RSA"
                passed("Host key type", f"{size_str} — meets minimum size requirement")
        elif key_type in ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"):
            curve = key_type.split("nistp")[1]
            passed("Host key type", f"ECDSA P-{curve}")
        elif key_type == "ssh-ed25519":
            passed("Host key type", "ED25519 — recommended")
        else:
            info("Host key type", key_type)

    except Exception as e:
        info("SSH Host Keys", f"could not retrieve host key — {e}")

    finally:
        if transport:
            transport.close()


def check_ssh_root_login(target: str) -> None:
    """Probe whether root login is enabled by sending a 'none' auth request.

    auth_none("root") asks the server to authenticate root using the 'none'
    method (no credentials). Two distinct responses are possible:

      BadAuthenticationType — server replied with a list of accepted methods.
          Root login is enabled. [FAIL]

      AuthenticationException — server rejected root outright.
          Root login is likely disabled (PermitRootLogin no). [PASS]

    Note: BadAuthenticationType is a subclass of AuthenticationException, so
    it must be caught first.
    """
    _thread_local.category = "SSH Root Login"
    print("\n[SSH Root Login]")

    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=_timeout)
        transport.auth_none("root")
        failed(
            "Root login",
            "enabled — authenticated as root with no credentials",
            "Set PermitRootLogin no in /etc/ssh/sshd_config and run: sudo systemctl reload sshd",
            severity="CRITICAL",
        )

    except paramiko.BadAuthenticationType as e:
        methods = ", ".join(e.allowed_types) if e.allowed_types else "unknown"
        failed(
            "Root login",
            f"enabled — server offered auth methods: {methods}",
            "Set PermitRootLogin no in /etc/ssh/sshd_config and run: sudo systemctl reload sshd",
            severity="CRITICAL",
        )

    except paramiko.AuthenticationException:
        passed("Root login", "disabled — server rejected auth for root")

    except Exception as e:
        info("Root login", f"could not determine — {e}")

    finally:
        if transport:
            transport.close()


def check_ssh_password_auth(target: str) -> None:
    """Probe whether password authentication is enabled on port 22.

    Sends an auth_password request with an obviously fake username and password.

      BadAuthenticationType — password auth is disabled. [PASS]
      AuthenticationException — password auth is enabled, credentials wrong. [FAIL]

    Note: BadAuthenticationType is a subclass of AuthenticationException, so
    it must be caught first.
    """
    _thread_local.category = "SSH Password Auth"
    print("\n[SSH Password Auth]")

    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=_timeout)
        transport.auth_password("__audit_probe__", "__audit_wrong_pw_12345__")
        failed(
            "Password authentication",
            "enabled — probe credentials unexpectedly authenticated",
            "Set PasswordAuthentication no in sshd_config. Ensure key-based auth works first.",
        )

    except paramiko.BadAuthenticationType:
        passed("Password authentication",
               "disabled — server does not accept password authentication")

    except paramiko.AuthenticationException:
        failed(
            "Password authentication",
            "enabled — server accepts password authentication",
            (
                "Disable password auth: set PasswordAuthentication no in sshd_config. "
                "Ensure SSH key-based login works first, then: sudo systemctl reload sshd"
            ),
            severity="CRITICAL",
        )

    except Exception as e:
        info("Password authentication", f"could not determine — {e}")

    finally:
        if transport:
            transport.close()


def check_ssh_legacy(target: str) -> None:
    """Identify potential legacy or embedded hardware by SSH algorithm fingerprint.

    Makes a single SSH connection to capture both the KEXINIT algorithm list and
    the server banner, then runs them against the device fingerprint database.

    Matching is attempted in two ways:

      Banner match (high confidence) — a known vendor string is found in the SSH
          version string: "dropbear", "cisco", "FGSSH", etc.

      Algorithm fingerprint (medium confidence) — the server advertises at least
          one indicator KEX algorithm (e.g. group14-sha1), none of the modern
          algorithms that a patched server would have (curve25519, ECDH), and
          at least one indicator cipher (e.g. aes128-cbc). Used to identify
          HP iLO 2/3 and similar BMCs that hide behind a generic OpenSSH banner.

    A matched device is reported as [INFO] with a remediation note.

    Two additional [FAIL] checks run independently of device identification:
      - No modern KEX available: only deprecated key exchange with no modern
        alternative means the connection cannot be made secure regardless of
        configuration on the client side.
      - No modern ciphers available: only CBC/RC4 modes advertised.
    """
    _thread_local.category = "SSH Legacy Detection"
    print("\n[SSH Legacy Detection]")

    captured, banner = _capture_kexinit(target)

    if not captured:
        info("Legacy detection", "could not retrieve algorithm list")
        return

    kex     = captured.get("kex", [])
    ciphers = captured.get("ciphers", [])
    kex_set = set(kex)
    cph_set = set(ciphers)

    # ── Device identification ──────────────────────────────────────────────────
    fp, method = _match_fingerprint(banner, kex, ciphers)

    legacy_remediation = (
        "Upgrade device firmware if available. If SSH cannot be secured, "
        "use an alternative management protocol (HTTPS/RIBCL) and isolate "
        "the device on a dedicated management VLAN."
    )

    if fp:
        confidence = "identified by banner" if method == "banner" else "identified by algorithm fingerprint"
        info("Device fingerprint", f"{fp['name']} ({confidence})")
        info("Recommendation", fp["note"])

        # Flag insecure algorithms specific to this device that are present
        # and have no modern counterpart in the same category.
        legacy_kex_present     = fp["insecure_kex"]     & kex_set
        legacy_ciphers_present = fp["insecure_ciphers"] & cph_set
        has_modern_kex         = bool(_MODERN_KEX & kex_set)
        has_modern_ciphers     = bool(cph_set - _LEGACY_CIPHERS)

        if legacy_kex_present and not has_modern_kex:
            failed(
                "Legacy KEX only",
                f"device supports only: {', '.join(sorted(legacy_kex_present))}",
                legacy_remediation,
                severity="CRITICAL",
            )
        if legacy_ciphers_present and not has_modern_ciphers:
            failed(
                "Legacy ciphers only",
                f"device supports only: {', '.join(sorted(legacy_ciphers_present))}",
                legacy_remediation,
            )
    else:
        # ── Standalone legacy checks (no specific device match) ────────────────
        has_legacy_kex     = bool(_LEGACY_KEX & kex_set)
        has_modern_kex     = bool(_MODERN_KEX & kex_set)
        has_modern_ciphers = bool(cph_set - _LEGACY_CIPHERS)

        if has_legacy_kex and not has_modern_kex:
            legacy_present = sorted(_LEGACY_KEX & kex_set)
            failed(
                "No modern key exchange available",
                f"only deprecated KEX advertised: {', '.join(legacy_present)}",
                legacy_remediation,
                severity="CRITICAL",
            )
        if ciphers and not has_modern_ciphers:
            failed(
                "No modern ciphers available",
                "only deprecated cipher modes (CBC/RC4) advertised",
                legacy_remediation,
            )

        if not (has_legacy_kex and not has_modern_kex) and not (ciphers and not has_modern_ciphers):
            passed("Legacy detection", "no known legacy device fingerprint detected")


def check_tls_versions(target: str) -> None:
    """Attempt a TLS handshake for each version against port 443.

    Each version is tested in isolation by setting both minimum_version and
    maximum_version on a fresh SSLContext, forcing the handshake to use only
    that version. TLS 1.0 and 1.1 are deprecated (RFC 8996) and should be
    disabled on any server — a successful handshake for either is a [FAIL].
    """
    _thread_local.category = "TLS Version Support"
    print("\n[TLS Version Support]")

    tls_legacy_remediation = (
        "Disable TLS 1.0 and 1.1 in your web server config. "
        "Nginx: ssl_protocols TLSv1.2 TLSv1.3;  "
        "Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
    )

    versions = [
        (getattr(ssl.TLSVersion, "TLSv1",   None), "TLS 1.0", False),
        (getattr(ssl.TLSVersion, "TLSv1_1", None), "TLS 1.1", False),
        (ssl.TLSVersion.TLSv1_2,                   "TLS 1.2", True),
        (ssl.TLSVersion.TLSv1_3,                   "TLS 1.3", True),
    ]

    for version, label, should_succeed in versions:
        if version is None:
            info(label, "not available in this Python/OpenSSL build")
            continue

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
        except ssl.SSLError:
            info(label, "not testable — disabled by local SSL policy")
            continue

        try:
            with socket.create_connection((target, 443), timeout=_timeout) as raw:
                with ctx.wrap_socket(raw):
                    if should_succeed:
                        passed(label, "supported")
                    else:
                        failed(label, "supported — should be disabled",
                               tls_legacy_remediation, severity="CRITICAL")
        except ssl.SSLError:
            if should_succeed:
                info(label, "not supported by server")
            else:
                passed(label, "not supported by server (correctly disabled)")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            info(label, f"could not reach port 443 — {e}")


def check_dns_caa(target: str) -> None:
    """Check whether the target domain has CAA DNS records.

    CAA (Certification Authority Authorization) records specify which CAs are
    allowed to issue certificates for the domain. A missing CAA record means
    any CA may issue a certificate — increasing the risk of misissued certs.

    Skipped for IP addresses.
    """
    _thread_local.category = "DNS / CAA"
    print("\n[DNS / CAA]")

    if _is_ip(target):
        info("CAA records", "skipped — target is an IP address")
        return

    try:
        answers = dns.resolver.resolve(target, "CAA")
        records = [str(r) for r in answers]
        passed("CAA records", f"{len(records)} record(s): {', '.join(records)}")
    except dns.resolver.NoAnswer:
        failed(
            "CAA records",
            "no CAA records — any CA may issue certificates for this domain",
            f'Add a CAA record. Example: {target} CAA 0 issue "letsencrypt.org"',
        )
    except dns.resolver.NXDOMAIN:
        info("CAA records", "domain does not exist")
    except dns.exception.DNSException as e:
        info("CAA records", f"DNS lookup failed — {e}")


def check_tls_ciphers(target: str) -> None:
    """Check whether port 443 accepts known weak cipher suites.

    For each weak cipher group a fresh SSLContext is created with only that
    group allowed. A successful handshake means the server accepts the weak
    cipher — [FAIL]. An SSLError on the handshake means the server refused
    it — [PASS]. If the local OpenSSL build does not include a cipher group
    at all, that group is silently skipped.
    """
    _thread_local.category = "TLS Cipher Suites"
    print("\n[TLS Cipher Suites]")

    weak_groups = [
        ("NULL ciphers",   "NULL",   "no encryption — data sent in cleartext",          "CRITICAL"),
        ("aNULL ciphers",  "aNULL",  "anonymous auth — no server identity verification", "CRITICAL"),
        ("EXPORT ciphers", "EXPORT", "export-grade 40/56-bit encryption — trivially broken", "CRITICAL"),
        ("RC4 ciphers",    "RC4",    "RC4 stream cipher — cryptographically broken",    "CRITICAL"),
        ("3DES ciphers",   "3DES",   "Triple DES — vulnerable to SWEET32 birthday attack", "WARNING"),
    ]

    remediation = (
        "Restrict cipher suites in your web server. "
        "Nginx: ssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM'; ssl_prefer_server_ciphers on;  "
        "Apache: SSLCipherSuite 'ECDHE+AESGCM:ECDHE+CHACHA20'"
    )

    reachable = True
    for label, cipher_str, description, sev in weak_groups:
        if not reachable:
            break

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher_str)
        except ssl.SSLError:
            continue  # cipher group not available in this OpenSSL build

        try:
            with socket.create_connection((target, 443), timeout=_timeout) as raw:
                with ctx.wrap_socket(raw) as ssock:
                    negotiated = ssock.cipher()[0] if ssock.cipher() else "unknown"
                    failed(label, f"server accepted {negotiated} — {description}",
                           remediation, severity=sev)
        except ssl.SSLError:
            passed(label, "not accepted by server")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            info(label, f"could not reach port 443 — {e}")
            reachable = False


def check_tls_certificate(target: str) -> None:
    """Retrieve the TLS certificate from port 443 and check:

      - Trust: chain verified against system CA bundle.
      - Expiry: [FAIL] if expired or < 30 days, [INFO] if < 90 days.
      - Hostname match: SAN list (DNS + IP) checked against target.
    """
    _thread_local.category = "TLS Certificate"
    print("\n[TLS Certificate]")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False

    cert = None
    try:
        with socket.create_connection((target, 443), timeout=_timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        msg = str(e)
        if "certificate verify failed:" in msg:
            reason = msg.split("certificate verify failed:")[1].split("(")[0].strip()
        else:
            reason = msg
        failed(
            "Certificate trust",
            reason,
            "Ensure the full certificate chain is installed and the cert is issued by a trusted CA.",
            severity="CRITICAL",
        )
        return
    except ssl.SSLError as e:
        info("TLS Certificate", f"TLS error — {e}")
        return
    except ConnectionRefusedError:
        info("TLS Certificate", "port 443 closed — skipping")
        return
    except (socket.timeout, OSError) as e:
        info("TLS Certificate", f"could not reach port 443 — {e}")
        return

    if not cert:
        info("TLS Certificate", "no certificate data returned")
        return

    issuer = dict(x[0] for x in cert.get("issuer", []))
    issuer_name = issuer.get("organizationName") or issuer.get("commonName", "unknown")
    passed("Certificate trust", f"issued by {issuer_name}")

    try:
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (not_after - now).days

        if days_left < 0:
            failed(
                "Certificate expiry",
                f"expired {abs(days_left)} day(s) ago ({not_after.date()})",
                "Renew the certificate immediately. certbot: sudo certbot renew --force-renewal",
                severity="CRITICAL",
            )
        elif days_left < 30:
            failed(
                "Certificate expiry",
                f"expires in {days_left} day(s) ({not_after.date()}) — renew immediately",
                "Renew the certificate now. certbot: sudo certbot renew",
                severity="CRITICAL",
            )
        elif days_left < 90:
            info("Certificate expiry",
                 f"expires in {days_left} day(s) ({not_after.date()}) — renewal recommended soon")
        else:
            passed("Certificate expiry",
                   f"valid for {days_left} more day(s) (expires {not_after.date()})")
    except (KeyError, ValueError):
        info("Certificate expiry", "could not parse expiry date")

    subject = dict(x[0] for x in cert.get("subject", []))
    if _is_ip(target):
        ip_sans = [addr for kind, addr in cert.get("subjectAltName", [])
                   if kind == "IP Address"]
        if target in ip_sans:
            passed("Hostname match", f"certificate covers IP {target}")
        elif ip_sans:
            failed(
                "Hostname match",
                f"certificate does not cover {target} — IP SANs: {', '.join(ip_sans)}",
                f"Reissue the certificate with IP SAN: {target}",
                severity="CRITICAL",
            )
        else:
            failed(
                "Hostname match",
                f"certificate has no IP SANs — does not cover {target}",
                f"Reissue the certificate with IP SAN: {target}",
                severity="CRITICAL",
            )
    else:
        dns_sans = [name for kind, name in cert.get("subjectAltName", [])
                    if kind == "DNS"]
        if dns_sans:
            if _hostname_matches(target, dns_sans):
                passed("Hostname match", f"certificate covers {target}")
            else:
                preview = ", ".join(dns_sans[:4])
                if len(dns_sans) > 4:
                    preview += f" (+{len(dns_sans) - 4} more)"
                failed(
                    "Hostname match",
                    f"certificate does not cover {target} — SANs: {preview}",
                    f"Reissue the certificate to include '{target}' in the Subject Alternative Name (SAN) field.",
                    severity="CRITICAL",
                )
        else:
            cn = subject.get("commonName", "")
            if cn and _hostname_matches(target, [cn]):
                passed("Hostname match", f"certificate CN matches {target}")
            else:
                failed(
                    "Hostname match",
                    f"certificate CN '{cn}' does not match {target}",
                    f"Reissue the certificate to include '{target}' in the Subject Alternative Name (SAN) field.",
                    severity="CRITICAL",
                )


def check_http_security(target: str) -> None:
    """Check HTTP→HTTPS redirect behaviour, HSTS, and security headers on port 443."""
    _thread_local.category = "HTTP Security"
    print("\n[HTTP Security]")

    try:
        conn = http.client.HTTPConnection(target, 80, timeout=_timeout)
        conn.request("GET", "/", headers={"Host": target,
                                          "User-Agent": "ssh-tls-auditor"})
        resp = conn.getresponse()
        location = resp.getheader("Location", "")
        if resp.status in (301, 302, 303, 307, 308) and location.lower().startswith("https://"):
            passed("HTTP → HTTPS redirect", f"HTTP {resp.status} → {location}")
        elif resp.status in (301, 302, 303, 307, 308):
            failed(
                "HTTP → HTTPS redirect",
                f"redirects to non-HTTPS location: {location or '(empty)'}",
                "Update the redirect to point to https://. Nginx: return 301 https://$host$request_uri;",
            )
        else:
            failed(
                "HTTP → HTTPS redirect",
                f"no redirect — server returned HTTP {resp.status} on port 80",
                "Add HTTP→HTTPS redirect. Nginx: return 301 https://$host$request_uri;  Apache: Redirect permanent / https://example.com/",
            )
        conn.close()
    except ConnectionRefusedError:
        info("HTTP → HTTPS redirect", "port 80 closed — skipping")
    except (socket.timeout, OSError) as e:
        info("HTTP → HTTPS redirect", f"could not reach port 80 — {e}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        conn = http.client.HTTPSConnection(target, 443, timeout=_timeout, context=ctx)
        conn.request("HEAD", "/", headers={"Host": target,
                                           "User-Agent": "ssh-tls-auditor"})
        resp = conn.getresponse()

        hsts  = resp.getheader("Strict-Transport-Security", "")
        xfo   = resp.getheader("X-Frame-Options", "")
        xcto  = resp.getheader("X-Content-Type-Options", "")
        csp   = resp.getheader("Content-Security-Policy", "")
        conn.close()

        # ── HSTS ──────────────────────────────────────────────────────────────
        if not hsts:
            failed(
                "HSTS header",
                "Strict-Transport-Security not present",
                "Add HSTS header. Nginx: add_header Strict-Transport-Security 'max-age=15552000; includeSubDomains' always;",
            )
        else:
            max_age: int | None = None
            for part in hsts.split(";"):
                part = part.strip()
                if part.lower().startswith("max-age="):
                    try:
                        max_age = int(part.split("=", 1)[1])
                    except ValueError:
                        pass

            include_subdomains = "includesubdomains" in hsts.lower()
            MIN_MAX_AGE = 15_552_000  # 180 days

            if max_age is None:
                failed("HSTS header", f"present but max-age could not be parsed: {hsts}",
                       "Fix the Strict-Transport-Security header format: max-age=15552000")
            elif max_age < MIN_MAX_AGE:
                days = max_age // 86400
                failed(
                    "HSTS header",
                    f"max-age too short — {days} day(s) (minimum recommended: 180 days)",
                    "Increase HSTS max-age to at least 15552000 (180 days).",
                )
            else:
                days = max_age // 86400
                detail = f"max-age={days} days"
                if include_subdomains:
                    detail += ", includeSubDomains"
                passed("HSTS header", detail)

        # ── X-Frame-Options ───────────────────────────────────────────────────
        if not xfo:
            failed(
                "X-Frame-Options",
                "header not present — site may be embeddable in iframes (clickjacking risk)",
                "Add header. Nginx: add_header X-Frame-Options 'SAMEORIGIN' always;",
            )
        elif xfo.upper() in ("DENY", "SAMEORIGIN"):
            passed("X-Frame-Options", xfo.upper())
        else:
            failed(
                "X-Frame-Options",
                f"unexpected value: {xfo}",
                "Set X-Frame-Options to DENY or SAMEORIGIN.",
            )

        # ── X-Content-Type-Options ────────────────────────────────────────────
        if not xcto:
            failed(
                "X-Content-Type-Options",
                "header not present — browsers may MIME-sniff responses",
                "Add header. Nginx: add_header X-Content-Type-Options 'nosniff' always;",
            )
        elif xcto.strip().lower() == "nosniff":
            passed("X-Content-Type-Options", "nosniff")
        else:
            failed(
                "X-Content-Type-Options",
                f"unexpected value: {xcto}",
                "Set X-Content-Type-Options to 'nosniff'.",
            )

        # ── Content-Security-Policy ───────────────────────────────────────────
        if not csp:
            failed(
                "Content-Security-Policy",
                "header not present — no CSP protection against XSS and injection attacks",
                "Add a Content-Security-Policy header. Start with: default-src 'self'",
            )
        else:
            passed("Content-Security-Policy", "present")

    except ConnectionRefusedError:
        info("HSTS / security headers", "port 443 closed — skipping")
    except (socket.timeout, OSError, ssl.SSLError) as e:
        info("HSTS / security headers", f"could not reach port 443 — {e}")


# ── TLS / hostname helpers ─────────────────────────────────────────────────────

def _hostname_matches(target: str, names: list[str]) -> bool:
    """Return True if target matches any name (supports *.example.com wildcards)."""
    target = target.lower()
    for name in names:
        name = name.lower()
        if name == target:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            rest   = target[: -len(suffix)]
            if target.endswith(suffix) and "." not in rest:
                return True
    return False


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ── CSV export ─────────────────────────────────────────────────────────────────

def write_csv(path: str) -> None:
    """Write all collected results to a CSV file."""
    fieldnames = ["host", "category", "check", "result", "detail", "remediation"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(_results)
    print(f"Results written to {path}")


# ── JSON export ────────────────────────────────────────────────────────────────

def write_json(path: str) -> None:
    """Write all collected results to a JSON file."""
    output = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "results":   _results,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)
    print(f"Results written to {path}")


# ── HTML export ────────────────────────────────────────────────────────────────

_HTML_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 14px;
       background: #f4f6f9; color: #222; padding: 24px; }
h1 { font-size: 24px; color: #1a3a5c; margin-bottom: 4px; }
.subtitle { color: #555; margin-bottom: 24px; font-size: 13px; }
h2 { font-size: 18px; color: #1a3a5c; margin: 32px 0 12px; border-bottom: 2px solid #1a3a5c; padding-bottom: 4px; }
h3 { font-size: 13px; font-weight: 600; color: #333; margin: 20px 0 6px;
     text-transform: uppercase; letter-spacing: 0.5px; }
table { width: 100%; border-collapse: collapse; margin-bottom: 16px; background: #fff;
        border-radius: 6px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
th { background: #1a3a5c; color: #fff; text-align: left; padding: 8px 12px;
     font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 7px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f9fbfd; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px;
         font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
.pass  { background: #e6f4ea; color: #1e7e34; }
.fail  { background: #fdecea; color: #c0392b; }
.info  { background: #e8f0fe; color: #1a56b0; }
.summary-box { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }
.summary-card { background: #fff; border-radius: 6px; padding: 16px 24px;
                box-shadow: 0 1px 4px rgba(0,0,0,0.1); min-width: 140px; text-align: center; }
.summary-card .number { font-size: 32px; font-weight: 700; }
.summary-card .label  { font-size: 12px; color: #777; margin-top: 2px; text-transform: uppercase; }
.num-pass { color: #1e7e34; }
.num-fail { color: #c0392b; }
.num-info { color: #1a56b0; }
.remediation-box { background: #fffbe6; border-left: 4px solid #f0ad00;
                   border-radius: 4px; padding: 8px 12px; margin-top: 4px;
                   font-size: 12px; color: #555; }
.remediation-label { font-weight: 600; color: #b07d00; margin-right: 4px; }
.host-block { background: #fff; border-radius: 8px; padding: 20px 24px;
              box-shadow: 0 2px 8px rgba(0,0,0,0.07); margin-bottom: 32px; }
"""

def write_html(path: str, targets: list[str]) -> None:
    """Write a self-contained HTML audit report."""
    e = html_module.escape
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    parts: list[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH/TLS Audit Report</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<h1>SSH/TLS Audit Report</h1>
<p class="subtitle">Generated: {e(now)}</p>
""")

    # ── Overall summary table ──────────────────────────────────────────────────
    host_counts: dict[str, dict[str, int]] = {}
    for row in _results:
        h = row["host"]
        if h not in host_counts:
            host_counts[h] = {"pass": 0, "fail": 0, "info": 0}
        host_counts[h][row["result"].lower()] += 1

    if len(targets) > 1:
        parts.append('<h2>Summary</h2>\n')
        parts.append('<table><thead><tr><th>Host</th><th>PASS</th><th>FAIL</th><th>INFO</th><th>Total</th></tr></thead><tbody>\n')
        for h in targets:
            c = host_counts.get(h, {"pass": 0, "fail": 0, "info": 0})
            total = c["pass"] + c["fail"] + c["info"]
            parts.append(
                f'<tr><td>{e(h)}</td>'
                f'<td><span class="badge pass">{c["pass"]}</span></td>'
                f'<td><span class="badge fail">{c["fail"]}</span></td>'
                f'<td><span class="badge info">{c["info"]}</span></td>'
                f'<td>{total}</td></tr>\n'
            )
        parts.append('</tbody></table>\n')

    # ── Per-host sections ──────────────────────────────────────────────────────
    for target in targets:
        host_results = [r for r in _results if r["host"] == target]
        c = host_counts.get(target, {"pass": 0, "fail": 0, "info": 0})
        total = c["pass"] + c["fail"] + c["info"]

        parts.append(f'<h2>{e(target)}</h2>\n<div class="host-block">\n')
        parts.append('<div class="summary-box">\n')
        parts.append(f'<div class="summary-card"><div class="number num-pass">{c["pass"]}</div><div class="label">Pass</div></div>\n')
        parts.append(f'<div class="summary-card"><div class="number num-fail">{c["fail"]}</div><div class="label">Fail</div></div>\n')
        parts.append(f'<div class="summary-card"><div class="number num-info">{c["info"]}</div><div class="label">Info</div></div>\n')
        parts.append(f'<div class="summary-card"><div class="number">{total}</div><div class="label">Total</div></div>\n')
        parts.append('</div>\n')

        # Group by category
        categories: dict[str, list[dict]] = {}
        for row in host_results:
            cat = row["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(row)

        for cat, rows in categories.items():
            parts.append(f'<h3>{e(cat)}</h3>\n')
            parts.append('<table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>\n')
            for row in rows:
                badge_cls = row["result"].lower()
                remediation_html = ""
                if row["result"] == "FAIL" and row.get("remediation"):
                    remediation_html = (
                        f'<div class="remediation-box">'
                        f'<span class="remediation-label">Fix:</span>{e(row["remediation"])}'
                        f'</div>'
                    )
                parts.append(
                    f'<tr>'
                    f'<td>{e(row["check"])}</td>'
                    f'<td><span class="badge {badge_cls}">{e(row["result"])}</span></td>'
                    f'<td>{e(row["detail"])}{remediation_html}</td>'
                    f'</tr>\n'
                )
            parts.append('</tbody></table>\n')

        parts.append('</div>\n')

    parts.append('</body></html>\n')

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    print(f"Results written to {path}")


# ── Grade computation ──────────────────────────────────────────────────────────

def compute_grade(target: str) -> str:
    """Return an A–F grade for target based on number of CRITICAL failures."""
    with _results_lock:
        criticals = sum(
            1 for r in _results
            if r["host"] == target and r["result"] == "FAIL"
            and r.get("severity") == "CRITICAL"
        )
    warnings = sum(
        1 for r in _results
        if r["host"] == target and r["result"] == "FAIL"
        and r.get("severity") != "CRITICAL"
    )
    if criticals == 0 and warnings == 0:
        return "A"
    if criticals == 0:
        return "B"
    if criticals == 1:
        return "C"
    if criticals <= 3:
        return "D"
    return "F"


# ── Config generator ───────────────────────────────────────────────────────────

def _config_block(title: str, lines: list[str]) -> None:
    """Print a labelled config snippet box to stdout."""
    width  = max(60, max((len(l) for l in lines), default=0) + 4)
    border = "─" * width
    label  = _colourise(f"  Suggested {title}", _ANSI_BLUE)
    print(f"\n{label}")
    print(f"  ┌{border}┐")
    for line in lines:
        print(f"  │  {line:<{width - 2}}│")
    print(f"  └{border}┘")


def generate_configs(target: str) -> None:
    """Generate ready-to-paste config snippets based on FAIL results for target.

    Builds an sshd_config section for SSH failures and an nginx section for
    TLS/HTTP failures. Only lines relevant to actual failures are included.
    """
    with _results_lock:
        snapshot = [r for r in _results if r["host"] == target and r["result"] == "FAIL"]

    if not snapshot:
        return

    fail_categories = {r["category"] for r in snapshot}
    fail_checks     = {r["check"]    for r in snapshot}

    # ── sshd_config ───────────────────────────────────────────────────────────
    ssh_cats = {"SSH Algorithms", "SSH Root Login", "SSH Password Auth",
                "SSH Host Keys",  "SSH Banner"}
    if fail_categories & ssh_cats:
        lines: list[str] = [
            "# /etc/ssh/sshd_config — apply changes, then:",
            "# sudo systemctl reload sshd",
            "",
        ]

        if "SSH Algorithms" in fail_categories:
            lines += [
                f"KexAlgorithms {_SSH_BEST_KEX}",
                f"Ciphers       {_SSH_BEST_CIPHERS}",
                f"MACs          {_SSH_BEST_MACS}",
                "",
            ]
        if "SSH Root Login" in fail_categories:
            lines.append("PermitRootLogin no")
        if "SSH Password Auth" in fail_categories:
            lines.append("PasswordAuthentication no")
        if "SSH Host Keys" in fail_categories:
            lines += [
                "",
                "# Regenerate host key (run as root, then reload sshd):",
                "# ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''",
            ]
        if "SSH Banner" in fail_categories:
            lines += [
                "",
                "# OpenSSH is outdated — upgrade the package:",
                "# sudo apt upgrade openssh-server  or  sudo dnf upgrade openssh-server",
            ]

        _config_block("sshd_config", lines)

    # ── nginx ─────────────────────────────────────────────────────────────────
    web_cats = {"TLS Version Support", "TLS Cipher Suites", "HTTP Security"}
    if fail_categories & web_cats:
        lines = [
            f"# nginx server block for {target}",
            "# Place inside your 'server {{ listen 443 ssl; ... }}' block.",
            "",
        ]

        if "TLS Version Support" in fail_categories:
            lines += ["ssl_protocols TLSv1.2 TLSv1.3;", ""]

        if "TLS Cipher Suites" in fail_categories:
            lines += [
                "ssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM';",
                "ssl_prefer_server_ciphers on;",
                "",
            ]

        if "HSTS header" in fail_checks:
            lines.append(
                "add_header Strict-Transport-Security 'max-age=15552000; includeSubDomains' always;"
            )
        if "X-Frame-Options" in fail_checks:
            lines.append("add_header X-Frame-Options 'SAMEORIGIN' always;")
        if "X-Content-Type-Options" in fail_checks:
            lines.append("add_header X-Content-Type-Options 'nosniff' always;")
        if "Content-Security-Policy" in fail_checks:
            lines.append("add_header Content-Security-Policy \"default-src 'self'\" always;")

        if "HTTP → HTTPS redirect" in fail_checks:
            lines += [
                "",
                "# Separate server block for HTTP → HTTPS redirect:",
                "server {",
                "    listen 80;",
                f"    server_name {target};",
                "    return 301 https://$host$request_uri;",
                "}",
            ]

        _config_block("nginx config", lines)


# ── Per-host audit ─────────────────────────────────────────────────────────────

def run_audit(target: str, only: set[str] | None = None) -> None:
    """Run all (or a subset of) checks against target and print the results."""
    _thread_local.host = target
    _reset_counts()

    all_groups = only is None

    title  = f"SSH/TLS Auditor — target: {target}"
    width  = max(38, len(title) + 2)
    border = "═" * width
    print(f"\n╔{border}╗")
    print(f"  {title}")
    print(f"╚{border}╝")

    if all_groups or "ports" in only:
        check_open_ports(target)
    if all_groups or "ssh" in only:
        check_ssh_algorithms(target)
        check_ssh_banner(target)
        check_ssh_host_keys(target)
        check_ssh_root_login(target)
        check_ssh_password_auth(target)
        check_ssh_legacy(target)
    if all_groups or "tls" in only:
        check_dns_caa(target)
        check_tls_versions(target)
        check_tls_ciphers(target)
        check_tls_certificate(target)
    if all_groups or "http" in only:
        check_http_security(target)

    c     = _counts()
    total = c["pass"] + c["fail"]
    grade = compute_grade(target)
    grade_str = _colourise(f"  Grade: {grade}", _GRADE_COLOURS[grade])
    print(f"\n╔{border}╗")
    print(f"  Summary — {total} checks")
    print(f"  [PASS] {c['pass']}   [FAIL] {c['fail']}   {grade_str}")
    if c["fail"] == 0:
        print("  All checks passed.")
    else:
        print(f"  {c['fail']} issue(s) require attention.")

        # Print remediation tips for this host's failures
        host_fails = [
            r for r in _results
            if r["host"] == target and r["result"] == "FAIL" and r.get("remediation")
        ]
        if host_fails:
            # Deduplicate remediation messages
            seen: set[str] = set()
            unique_fails = []
            for r in host_fails:
                if r["remediation"] not in seen:
                    seen.add(r["remediation"])
                    unique_fails.append(r)

            print(f"\n  Recommended actions:")
            for r in unique_fails:
                print(f"  • {r['check']}: {r['remediation']}")

    print(f"╚{border}╝")

    if _config:
        generate_configs(target)


def run_audit_buffered(target: str, only: set[str] | None) -> str:
    """Run run_audit() with stdout captured per-thread and return it as a string.

    Sets _thread_local.output to a StringIO buffer so that the
    _ThreadLocalStdout dispatcher routes this thread's print() calls into
    the buffer instead of the real stdout. Other threads are unaffected.
    """
    _thread_local.output = io.StringIO()
    try:
        run_audit(target, only)
        return _thread_local.output.getvalue()
    finally:
        _thread_local.output = None


# ── Multi-host summary ─────────────────────────────────────────────────────────

def print_multi_summary(targets: list[str]) -> None:
    """Print a condensed per-host table after scanning multiple targets."""
    host_counts: dict[str, dict[str, int]] = {}
    with _results_lock:
        snapshot = list(_results)

    for row in snapshot:
        h = row["host"]
        if h not in host_counts:
            host_counts[h] = {"pass": 0, "fail": 0}
        if row["result"] == "PASS":
            host_counts[h]["pass"] += 1
        elif row["result"] == "FAIL":
            host_counts[h]["fail"] += 1

    col_width = max(len(h) for h in targets) + 2
    border    = "═" * (col_width + 26)
    print(f"\n╔{border}╗")
    print("  Multi-host summary")
    print(f"  {'Host':<{col_width}} {'PASS':>6}  {'FAIL':>6}  {'Total':>6}")
    print(f"  {'─' * (col_width + 24)}")
    for h in targets:
        c     = host_counts.get(h, {"pass": 0, "fail": 0})
        total = c["pass"] + c["fail"]
        print(f"  {h:<{col_width}} {c['pass']:>6}  {c['fail']:>6}  {total:>6}")
    print(f"╚{border}╝")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH/TLS misconfiguration auditor",
        epilog=(
            "Examples:\n"
            "  auditor.py example.com\n"
            "  auditor.py host1 host2 host3 --csv results.csv\n"
            "  auditor.py example.com --html report.html\n"
            "  auditor.py example.com --json report.json\n"
            "  auditor.py -f hosts.txt --parallel --timeout 10\n"
            "  auditor.py example.com --only ssh tls"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets", nargs="*", metavar="TARGET",
        help="hostname(s) or IP address(es) to audit",
    )
    parser.add_argument(
        "-f", "--file", metavar="FILE",
        help="read targets from a file, one per line (# comments supported)",
    )
    parser.add_argument(
        "--csv", metavar="FILE",
        help="write results to a CSV file after all audits complete",
    )
    parser.add_argument(
        "--html", metavar="FILE",
        help="write results to a self-contained HTML report",
    )
    parser.add_argument(
        "--json", metavar="FILE",
        help="write results to a JSON file",
    )
    parser.add_argument(
        "--timeout", type=int, default=5, metavar="SECONDS",
        help="connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--only", nargs="+", choices=list(CHECK_GROUPS), metavar="GROUP",
        help=f"run only the specified check group(s): {', '.join(CHECK_GROUPS)}",
    )
    parser.add_argument(
        "--parallel", action="store_true",
        help="scan multiple targets in parallel (default: sequential)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="only print FAIL results — suppress PASS and INFO",
    )
    parser.add_argument(
        "--config", action="store_true",
        help="after each audit, print suggested sshd_config and nginx snippets for all failures",
    )
    parser.add_argument(
        "--badge", action="store_true",
        help="print a Markdown badge for each target after the audit",
    )
    args = parser.parse_args()

    global _timeout, _quiet, _config
    _timeout = args.timeout
    _quiet   = args.quiet
    _config  = args.config

    only: set[str] | None = set(args.only) if args.only else None

    targets: list[str] = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        parser.print_help()
        sys.exit(1)

    if args.parallel and len(targets) > 1:
        max_workers = min(len(targets), 20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_audit_buffered, t, only) for t in targets]
            for future in futures:
                print(future.result(), end="")
    else:
        for target in targets:
            run_audit(target, only)

    if len(targets) > 1:
        print_multi_summary(targets)

    if args.csv:
        write_csv(args.csv)

    if args.html:
        write_html(args.html, targets)

    if args.json:
        write_json(args.json)

    if args.badge:
        print("\nMarkdown badges:")
        for t in targets:
            grade  = compute_grade(t)
            colour = _BADGE_COLOURS[grade]
            label  = t.replace("-", "--").replace("_", "__")
            url    = f"https://img.shields.io/badge/{label}-{grade}-{colour}"
            print(f"  ![{t}]({url})")

    # Exit with code 1 if any check failed — useful in CI/CD pipelines
    has_failures = any(r["result"] == "FAIL" for r in _results)
    sys.exit(1 if has_failures else 0)


if __name__ == "__main__":
    main()
