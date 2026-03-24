"""UCP Directory Node Verifier.

Crawls registered UCP nodes, validates their /.well-known/ucp profiles,
and updates registry.json with current verification status.
"""

import contextlib
import ipaddress
import json
import re
import socket
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import jsonschema
import requests

REGISTRY_PATH = Path(__file__).parent.parent / "registry.json"
SCHEMA_PATH = Path(__file__).parent / "ucp_profile_schema.json"

REQUEST_TIMEOUT = 10
MAX_RESPONSE_BYTES = 65536
MAX_REDIRECTS = 3
MAX_FAILURES_BEFORE_OFFLINE = 3
MAX_STRING_LENGTH = 500
MAX_CAPABILITIES = 50

USER_AGENT = (
    "Mozilla/5.0 (compatible; UCP-Directory-Verifier/1.0; "
    "+https://hungry-ucp.dev)"
)

# Characters to strip from profile strings (control, bidi, zero-width, tags)
CONTROL_CHARS = re.compile(
    r"[\u0000-\u001f\u007f-\u009f"
    r"\u200b-\u200f\u2028-\u202e"
    r"\u2060-\u206f\ufeff\ufff9-\ufffc"
    r"\ue0000-\ue007f\ufe00-\ufe0f"
    r"\ufdd0-\ufdef]"
)

# Valid domain: letters, digits, hyphens, dots, 2+ char TLD
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Valid capability identifier: alphanumeric with dots, underscores, hyphens
CAP_RE = re.compile(r"^[a-zA-Z0-9._-]{1,200}$")


def _err(msg: str) -> None:
    """Print error to stderr."""
    print(msg, file=sys.stderr)


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private, loopback, or link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return True


def resolve_domain(domain: str) -> str | None:
    """Resolve domain to IP, rejecting private addresses."""
    try:
        results = socket.getaddrinfo(domain, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if not is_private_ip(ip):
                return ip
        return None
    except socket.gaierror:
        return None


@contextlib.contextmanager
def _pinned_dns(domain: str, ip: str):
    """Context manager that patches socket.getaddrinfo to return a pinned IP.

    This prevents DNS rebinding attacks by ensuring the IP validated at
    resolve time is the same IP used for the actual TCP connection.
    Single-threaded only — safe for this CI script.
    """
    original_getaddrinfo = socket.getaddrinfo

    def pinned_getaddrinfo(host, port, *args, **kwargs):
        if host == domain:
            # Return the pre-validated IP with correct address family
            addr = ipaddress.ip_address(ip)
            if addr.version == 6:
                return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", (ip, port or 443, 0, 0))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 443))]
        return original_getaddrinfo(host, port, *args, **kwargs)

    socket.getaddrinfo = pinned_getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


def sanitize_string(value: object) -> str:
    """Strip control characters and truncate."""
    if not isinstance(value, str):
        return str(value)[:MAX_STRING_LENGTH] if value is not None else ""
    cleaned = CONTROL_CHARS.sub("", value)
    return cleaned[:MAX_STRING_LENGTH]


def fetch_ucp_profile(domain: str) -> dict | None:
    """Fetch and validate a UCP profile from a domain.

    Security measures:
    - Domain format validation (rejects path traversal, port injection)
    - DNS resolution with private IP rejection
    - Pinned DNS to prevent rebinding (TOCTOU)
    - Manual redirect following with per-hop SSRF validation
    - Reject scheme downgrades (https only)
    - Streamed response with size cap
    - Schema validation and string sanitization
    """
    if not DOMAIN_RE.match(domain):
        _err(f"  [{domain}] Invalid domain format")
        return None

    ip = resolve_domain(domain)
    if ip is None:
        _err(f"  [{domain}] DNS resolution failed or resolved to private IP")
        return None

    url = f"https://{domain}/.well-known/ucp"

    # Pin DNS for the duration of all requests to this domain
    with _pinned_dns(domain, ip):
        try:
            session = requests.Session()
            session.trust_env = False  # Prevent proxy env vars from bypassing DNS pinning

            # Follow redirects manually to validate each hop
            current_url = url
            resp = None
            for _ in range(MAX_REDIRECTS + 1):
                resp = session.get(
                    current_url,
                    timeout=REQUEST_TIMEOUT,
                    headers={"User-Agent": USER_AGENT},
                    allow_redirects=False,
                    stream=True,
                )

                if resp.status_code not in (301, 302, 303, 307, 308):
                    break

                raw_redirect = resp.headers.get("Location")
                resp.close()
                if not raw_redirect:
                    break

                # Resolve relative redirects against the current URL
                redirect_url = urljoin(current_url, raw_redirect)
                parsed = urlparse(redirect_url)

                # Reject scheme downgrades
                if parsed.scheme != "https":
                    _err(f"  [{domain}] Redirect to non-HTTPS scheme, rejecting")
                    return None

                # Reject non-standard ports
                if parsed.port and parsed.port != 443:
                    _err(f"  [{domain}] Redirect to non-standard port {parsed.port}, rejecting")
                    return None

                redirect_host = parsed.hostname
                if not redirect_host or redirect_host != domain:
                    _err(f"  [{domain}] Cross-domain redirect to {redirect_host}, rejecting")
                    return None

                current_url = redirect_url

            if resp is None or resp.status_code != 200:
                status = resp.status_code if resp else "no response"
                _err(f"  [{domain}] HTTP {status}")
                if resp:
                    resp.close()
                return None

            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                _err(f"  [{domain}] Unexpected content-type: {content_type}")
                resp.close()
                return None

            # Stream response with size cap (prevents memory exhaustion)
            chunks = []
            bytes_read = 0
            for chunk in resp.iter_content(chunk_size=8192):
                bytes_read += len(chunk)
                if bytes_read > MAX_RESPONSE_BYTES:
                    _err(f"  [{domain}] Response exceeds {MAX_RESPONSE_BYTES} bytes")
                    resp.close()
                    return None
                chunks.append(chunk)
            resp.close()

            content = b"".join(chunks)
            data = json.loads(content.decode("utf-8"))

            if not isinstance(data, dict):
                _err(f"  [{domain}] Profile is not a JSON object")
                return None

            # Schema validation
            if SCHEMA_PATH.exists():
                schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
                jsonschema.validate(data, schema)

            return data

        except requests.exceptions.Timeout:
            _err(f"  [{domain}] Request timed out ({REQUEST_TIMEOUT}s)")
        except requests.exceptions.ConnectionError as e:
            _err(f"  [{domain}] Connection error: {e}")
        except json.JSONDecodeError:
            _err(f"  [{domain}] Invalid JSON response")
        except UnicodeDecodeError:
            _err(f"  [{domain}] Response is not valid UTF-8")
        except jsonschema.ValidationError as e:
            _err(f"  [{domain}] Schema validation failed: {e.message}")

    return None


def extract_capabilities(profile: dict) -> list[str]:
    """Extract capability names from a UCP profile.

    Only reads from ucp.capabilities (the spec-defined registry).
    Does NOT read ucp.services (those are transports, not capabilities).
    """
    caps = []
    ucp = profile.get("ucp", {})

    if not isinstance(ucp, dict):
        return caps

    val = ucp.get("capabilities")
    if isinstance(val, dict):
        for k in val.keys():
            s = sanitize_string(k)
            if CAP_RE.match(s):
                caps.append(s)
    elif isinstance(val, list):
        for c in val:
            s = sanitize_string(c)
            if CAP_RE.match(s):
                caps.append(s)

    return caps[:MAX_CAPABILITIES]


def extract_version(profile: dict) -> str | None:
    """Extract UCP spec version from a profile."""
    ucp = profile.get("ucp", {})
    if isinstance(ucp, dict):
        version = ucp.get("version")
        if version:
            s = sanitize_string(version)
            if re.match(r"^\d[\d.\-]{0,20}$", s):
                return s
    return None


def verify_nodes() -> None:
    """Main verification loop."""
    if not REGISTRY_PATH.exists():
        _err("registry.json not found")
        sys.exit(1)

    nodes = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    if not isinstance(nodes, list):
        _err("registry.json is not a JSON array")
        sys.exit(1)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"Verifying {len(nodes)} nodes at {now}\n")

    for node in nodes:
        if not isinstance(node, dict):
            continue

        domain = node.get("domain", "")
        print(f"Checking {domain}...")

        profile = fetch_ucp_profile(domain)

        if profile is not None:
            node["status"] = "verified"
            node["capabilities"] = extract_capabilities(profile)
            node["profile_url"] = f"https://{domain}/.well-known/ucp"
            node["last_verified"] = now
            node["failure_count"] = 0
            node["ucp_version"] = extract_version(profile)
            print(f"  [{domain}] Verified successfully")
        else:
            node["failure_count"] = node.get("failure_count", 0) + 1

            if (
                node.get("status") == "verified"
                and node["failure_count"] >= MAX_FAILURES_BEFORE_OFFLINE
            ):
                node["status"] = "offline"
                print(f"  [{domain}] Marked offline after {node['failure_count']} failures")
            else:
                print(f"  [{domain}] Check failed (failure_count: {node['failure_count']})")

        node["last_checked"] = now

    # Atomic write: unique temp file then replace (cross-platform safe)
    fd, tmp_path = tempfile.mkstemp(
        dir=REGISTRY_PATH.parent, suffix=".tmp", prefix="registry_"
    )
    try:
        with open(fd, "w", encoding="utf-8") as f:
            json.dump(nodes, f, indent=2)
            f.write("\n")
        Path(tmp_path).replace(REGISTRY_PATH)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise

    print("\nDone. Registry updated.")


if __name__ == "__main__":
    verify_nodes()
