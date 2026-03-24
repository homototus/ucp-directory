"""UCP Directory Node Verifier.

Crawls registered UCP nodes, validates their /.well-known/ucp profiles,
and updates registry.json with current verification status.
"""

import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

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


def sanitize_string(value: object) -> str:
    """Strip control characters and truncate."""
    if not isinstance(value, str):
        return str(value)[:MAX_STRING_LENGTH] if value is not None else ""
    cleaned = CONTROL_CHARS.sub("", value)
    return cleaned[:MAX_STRING_LENGTH]


def fetch_ucp_profile(domain: str) -> dict | None:
    """Fetch and validate a UCP profile from a domain.

    Security: manually follows redirects to validate each hop against SSRF.
    Pins resolved IP to prevent DNS rebinding (TOCTOU).
    Streams response with size cap.
    """
    if not DOMAIN_RE.match(domain):
        print(f"  [{domain}] Invalid domain format")
        return None

    ip = resolve_domain(domain)
    if ip is None:
        print(f"  [{domain}] DNS resolution failed or resolved to private IP")
        return None

    url = f"https://{domain}/.well-known/ucp"

    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.connection import create_connection

        # Custom adapter that pins DNS resolution to our pre-validated IP.
        # This prevents DNS rebinding attacks where the domain resolves to
        # a different (internal) IP between our check and the actual connection.
        class PinnedIPAdapter(HTTPAdapter):
            def __init__(self, pinned_ip: str, **kwargs):
                self.pinned_ip = pinned_ip
                super().__init__(**kwargs)

            def init_poolmanager(self, *args, **kwargs):
                # Override socket creation to connect to pinned IP
                original_create_connection = create_connection

                pinned = self.pinned_ip

                def patched_create_connection(address, *a, **kw):
                    host, port = address
                    return original_create_connection((pinned, port), *a, **kw)

                import urllib3.util.connection
                urllib3.util.connection.create_connection = patched_create_connection
                try:
                    super().init_poolmanager(*args, **kwargs)
                finally:
                    urllib3.util.connection.create_connection = original_create_connection

        session = requests.Session()
        session.mount("https://", PinnedIPAdapter(ip))

        # Follow redirects manually to validate each hop
        current_url = url
        resp = None
        for _ in range(MAX_REDIRECTS + 1):
            resp = session.get(
                current_url,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT, "Host": domain},
                allow_redirects=False,
                stream=True,
            )

            if resp.status_code not in (301, 302, 303, 307, 308):
                break

            redirect_url = resp.headers.get("Location")
            resp.close()
            if not redirect_url:
                break

            redirect_host = urlparse(redirect_url).hostname
            if not redirect_host or redirect_host != domain:
                print(f"  [{domain}] Cross-domain redirect to {redirect_host}, rejecting")
                return None

            # Re-validate IP for redirect target
            redirect_ip = resolve_domain(redirect_host)
            if redirect_ip is None:
                print(f"  [{domain}] Redirect target resolves to private IP")
                return None

            current_url = redirect_url

        if resp is None or resp.status_code != 200:
            status = resp.status_code if resp else "no response"
            print(f"  [{domain}] HTTP {status}")
            return None

        content_type = resp.headers.get("content-type", "")
        if "json" not in content_type:
            print(f"  [{domain}] Unexpected content-type: {content_type}")
            resp.close()
            return None

        # Stream response with size cap (prevents memory exhaustion)
        chunks = []
        bytes_read = 0
        for chunk in resp.iter_content(chunk_size=8192):
            bytes_read += len(chunk)
            if bytes_read > MAX_RESPONSE_BYTES:
                print(f"  [{domain}] Response exceeds {MAX_RESPONSE_BYTES} bytes")
                resp.close()
                return None
            chunks.append(chunk)
        resp.close()

        content = b"".join(chunks)
        data = json.loads(content.decode("utf-8"))

        if not isinstance(data, dict):
            print(f"  [{domain}] Profile is not a JSON object")
            return None

        # Schema validation if we have a schema file
        if SCHEMA_PATH.exists():
            import jsonschema
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            jsonschema.validate(data, schema)

        return data

    except Exception as e:
        error_type = type(e).__name__
        print(f"  [{domain}] {error_type}: {e}")
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
            # Accept YYYY-MM-DD or semver-like patterns
            if re.match(r"^\d[\d.\-]{0,20}$", s):
                return s
    return None


def verify_nodes() -> None:
    """Main verification loop."""
    if not REGISTRY_PATH.exists():
        print("registry.json not found")
        sys.exit(1)

    nodes = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    if not isinstance(nodes, list):
        print("registry.json is not a JSON array")
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

    # Atomic write: write to temp file then rename
    tmp_path = REGISTRY_PATH.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(nodes, indent=2) + "\n", encoding="utf-8")
    tmp_path.rename(REGISTRY_PATH)
    print("\nDone. Registry updated.")


if __name__ == "__main__":
    verify_nodes()
