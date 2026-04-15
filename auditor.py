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
    python3 auditor.py -f hosts.txt --parallel --timeout 10
    python3 auditor.py example.com --only ssh tls
"""

import argparse
import concurrent.futures
import contextlib
import csv
import datetime
import http.client
import io
import ipaddress
import socket
import ssl
import sys
import threading
import warnings

import paramiko
import paramiko.message


# ── Module-level configuration ─────────────────────────────────────────────────

_timeout: int = 5
CHECK_GROUPS = ("ports", "ssh", "tls", "http")


# ── Thread-local result tracking ───────────────────────────────────────────────

_thread_local = threading.local()

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

def _record(result: str, label: str, detail: str) -> None:
    with _results_lock:
        _results.append({
            "host":     _host(),
            "category": _category(),
            "check":    label,
            "result":   result,
            "detail":   detail,
        })


def passed(label: str, detail: str = "") -> None:
    _counts()["pass"] += 1
    _record("PASS", label, detail)
    line = f"  [PASS]  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def failed(label: str, detail: str = "") -> None:
    _counts()["fail"] += 1
    _record("FAIL", label, detail)
    line = f"  [FAIL]  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def info(label: str, detail: str = "") -> None:
    _record("INFO", label, detail)
    line = f"  [INFO]  {label}"
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
# should be flagged as [FAIL] when present and have no modern counterpart.

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
    for port, label in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                passed(f"Port {port} ({label})", "open")
            else:
                failed(f"Port {port} ({label})", "closed")
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

    def evaluate(label: str, algos: list, weak_set: set) -> None:
        print(f"  {label}:")
        for algo in algos:
            if algo in weak_set:
                failed(algo, "deprecated")
            else:
                passed(algo)

    evaluate("Key exchange", captured.get("kex", []), WEAK_KEX)
    evaluate("Ciphers",      captured.get("ciphers", []), WEAK_CIPHERS)
    evaluate("MACs",         captured.get("macs", []), WEAK_MACS)


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
        failed("OpenSSH version", f"{raw} — outdated (< 8.0), upgrade recommended")
    else:
        passed("OpenSSH version", f"{raw} — current")


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
        failed("Root login", "enabled — authenticated as root with no credentials")

    except paramiko.BadAuthenticationType as e:
        methods = ", ".join(e.allowed_types) if e.allowed_types else "unknown"
        failed("Root login", f"enabled — server offered auth methods: {methods}")

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
        failed("Password authentication",
               "enabled — probe credentials unexpectedly authenticated")

    except paramiko.BadAuthenticationType:
        passed("Password authentication",
               "disabled — server does not accept password authentication")

    except paramiko.AuthenticationException:
        failed("Password authentication",
               "enabled — server accepts password authentication")

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

    if fp:
        confidence = "identified by banner" if method == "banner" else "identified by algorithm fingerprint"
        info("Device fingerprint", f"{fp['name']} ({confidence})")
        info("Recommendation", fp["note"])

        # Flag insecure algorithms specific to this device that are present
        # and have no modern counterpart in the same category.
        legacy_kex_present    = fp["insecure_kex"]    & kex_set
        legacy_ciphers_present = fp["insecure_ciphers"] & cph_set
        has_modern_kex    = bool(_MODERN_KEX & kex_set)
        has_modern_ciphers = bool(cph_set - _LEGACY_CIPHERS)

        if legacy_kex_present and not has_modern_kex:
            failed("Legacy KEX only",
                   f"device supports only: {', '.join(sorted(legacy_kex_present))}")
        if legacy_ciphers_present and not has_modern_ciphers:
            failed("Legacy ciphers only",
                   f"device supports only: {', '.join(sorted(legacy_ciphers_present))}")
    else:
        # ── Standalone legacy checks (no specific device match) ────────────────
        has_legacy_kex    = bool(_LEGACY_KEX & kex_set)
        has_modern_kex    = bool(_MODERN_KEX & kex_set)
        has_modern_ciphers = bool(cph_set - _LEGACY_CIPHERS)

        if has_legacy_kex and not has_modern_kex:
            legacy_present = sorted(_LEGACY_KEX & kex_set)
            failed("No modern key exchange available",
                   f"only deprecated KEX advertised: {', '.join(legacy_present)}")
        if ciphers and not has_modern_ciphers:
            failed("No modern ciphers available",
                   "only deprecated cipher modes (CBC/RC4) advertised")

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
                        failed(label, "supported — should be disabled")
        except ssl.SSLError:
            if should_succeed:
                info(label, "not supported by server")
            else:
                passed(label, "not supported by server (correctly disabled)")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            info(label, f"could not reach port 443 — {e}")


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
        failed("Certificate trust", reason)
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
            failed("Certificate expiry",
                   f"expired {abs(days_left)} day(s) ago ({not_after.date()})")
        elif days_left < 30:
            failed("Certificate expiry",
                   f"expires in {days_left} day(s) ({not_after.date()}) — renew immediately")
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
            failed("Hostname match",
                   f"certificate does not cover {target} — IP SANs: {', '.join(ip_sans)}")
        else:
            failed("Hostname match",
                   f"certificate has no IP SANs — does not cover {target}")
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
                failed("Hostname match",
                       f"certificate does not cover {target} — SANs: {preview}")
        else:
            cn = subject.get("commonName", "")
            if cn and _hostname_matches(target, [cn]):
                passed("Hostname match", f"certificate CN matches {target}")
            else:
                failed("Hostname match",
                       f"certificate CN '{cn}' does not match {target}")


def check_http_security(target: str) -> None:
    """Check HTTP→HTTPS redirect behaviour and HSTS header on port 443."""
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
            failed("HTTP → HTTPS redirect",
                   f"redirects to non-HTTPS location: {location or '(empty)'}")
        else:
            failed("HTTP → HTTPS redirect",
                   f"no redirect — server returned HTTP {resp.status} on port 80")
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
        hsts = resp.getheader("Strict-Transport-Security", "")
        conn.close()

        if not hsts:
            failed("HSTS header", "Strict-Transport-Security not present")
            return

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
            failed("HSTS header", f"present but max-age could not be parsed: {hsts}")
        elif max_age < MIN_MAX_AGE:
            days = max_age // 86400
            failed("HSTS header",
                   f"max-age too short — {days} day(s) (minimum recommended: 180 days)")
        else:
            days = max_age // 86400
            detail = f"max-age={days} days"
            if include_subdomains:
                detail += ", includeSubDomains"
            passed("HSTS header", detail)

    except ConnectionRefusedError:
        info("HSTS header", "port 443 closed — skipping")
    except (socket.timeout, OSError, ssl.SSLError) as e:
        info("HSTS header", f"could not reach port 443 — {e}")


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
    fieldnames = ["host", "category", "check", "result", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(_results)
    print(f"Results written to {path}")


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
        check_ssh_root_login(target)
        check_ssh_password_auth(target)
        check_ssh_legacy(target)
    if all_groups or "tls" in only:
        check_tls_versions(target)
        check_tls_certificate(target)
    if all_groups or "http" in only:
        check_http_security(target)

    c     = _counts()
    total = c["pass"] + c["fail"]
    print(f"\n╔{border}╗")
    print(f"  Summary — {total} checks")
    print(f"  [PASS] {c['pass']}   [FAIL] {c['fail']}")
    if c["fail"] == 0:
        print("  All checks passed.")
    else:
        print(f"  {c['fail']} issue(s) require attention.")
    print(f"╚{border}╝")


def run_audit_buffered(target: str, only: set[str] | None) -> str:
    """Run run_audit() with stdout captured and return it as a string."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_audit(target, only)
    return buf.getvalue()


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
    args = parser.parse_args()

    global _timeout
    _timeout = args.timeout

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


if __name__ == "__main__":
    main()
