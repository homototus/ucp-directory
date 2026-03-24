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

try:
    import jsonschema
    import requests
except ImportError:
    print("Missing dependencies. Run: pip install requests jsonschema")
    sys.exit(1)

REGISTRY_PATH = Path(__file__).parent.parent / "registry.json"
SCHEMA_PATH = Path(__file__).parent / "ucp_profile_schema.json"

REQUEST_TIMEOUT = 10
MAX_RESPONSE_BYTES = 65536
MAX_REDIRECTS = 3
MAX_FAILURES_BEFORE_OFFLINE = 3
MAX_STRING_LENGTH = 500

USER_AGENT = (
    "Mozilla/5.0 (compatible; UCP-Directory-Verifier/1.0; "
    "+https://hungry-ucp.dev)"
)

# Characters to strip from profile strings
CONTROL_CHARS = re.compile(
    r"[\u0000-\u001f\u007f-\u009f"
    r"\u200b-\u200f\u2028-\u202f"
    r"\u2060-\u206f\ufeff\ufff9-\ufffc]"
)


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
        for family, _, _, _, sockaddr in results:
            ip = sockaddr[0]
            if not is_private_ip(ip):
                return ip
        return None
    except socket.gaierror:
        return None


def sanitize_string(value: str) -> str:
    """Strip control characters and truncate."""
    if not isinstance(value, str):
        return ""
    cleaned = CONTROL_CHARS.sub("", value)
    return cleaned[:MAX_STRING_LENGTH]


def fetch_ucp_profile(domain: str) -> dict | None:
    """Fetch and validate a UCP profile from a domain."""
    ip = resolve_domain(domain)
    if ip is None:
        print(f"  [{domain}] DNS resolution failed or resolved to private IP")
        return None

    url = f"https://{domain}/.well-known/ucp"

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS

        resp = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            stream=True,
        )

        # Check for cross-domain redirects
        if resp.url and resp.url.startswith("http"):
            from urllib.parse import urlparse
            redirect_host = urlparse(resp.url).hostname
            if redirect_host and redirect_host != domain:
                print(f"  [{domain}] Cross-domain redirect to {redirect_host}, rejecting")
                return None

        if resp.status_code != 200:
            print(f"  [{domain}] HTTP {resp.status_code}")
            return None

        content_type = resp.headers.get("content-type", "")
        if "json" not in content_type and "octet-stream" not in content_type:
            print(f"  [{domain}] Unexpected content-type: {content_type}")
            return None

        # Read with size limit
        content = resp.content[:MAX_RESPONSE_BYTES]
        if len(resp.content) > MAX_RESPONSE_BYTES:
            print(f"  [{domain}] Response exceeds {MAX_RESPONSE_BYTES} bytes, truncated")

        data = json.loads(content)

        # Schema validation if we have a schema file
        if SCHEMA_PATH.exists():
            schema = json.loads(SCHEMA_PATH.read_text())
            jsonschema.validate(data, schema)

        return data

    except requests.exceptions.Timeout:
        print(f"  [{domain}] Request timed out ({REQUEST_TIMEOUT}s)")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"  [{domain}] Connection error: {e}")
        return None
    except json.JSONDecodeError:
        print(f"  [{domain}] Invalid JSON response")
        return None
    except jsonschema.ValidationError as e:
        print(f"  [{domain}] Schema validation failed: {e.message}")
        return None
    except Exception as e:
        print(f"  [{domain}] Unexpected error: {e}")
        return None


def extract_capabilities(profile: dict) -> list[str]:
    """Extract capability names from a UCP profile."""
    caps = []
    ucp = profile.get("ucp", {})

    # Try common locations for capabilities in UCP profiles
    if isinstance(ucp, dict):
        for key in ("capabilities", "services", "supported_capabilities"):
            val = ucp.get(key)
            if isinstance(val, list):
                caps.extend(sanitize_string(str(c)) for c in val if c)
            elif isinstance(val, dict):
                caps.extend(sanitize_string(str(k)) for k in val.keys())

    return caps


def extract_version(profile: dict) -> str | None:
    """Extract UCP version from a profile."""
    ucp = profile.get("ucp", {})
    if isinstance(ucp, dict):
        version = ucp.get("version") or ucp.get("spec_version")
        if version:
            return sanitize_string(str(version))
    return None


def verify_nodes():
    """Main verification loop."""
    if not REGISTRY_PATH.exists():
        print("registry.json not found")
        sys.exit(1)

    nodes = json.loads(REGISTRY_PATH.read_text())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"Verifying {len(nodes)} nodes at {now}\n")

    for node in nodes:
        domain = node.get("domain", "")
        print(f"Checking {domain}...")

        profile = fetch_ucp_profile(domain)

        if profile is not None:
            # Successful verification
            node["status"] = "verified"
            node["capabilities"] = extract_capabilities(profile)
            node["profile_url"] = f"https://{domain}/.well-known/ucp"
            node["last_verified"] = now
            node["failure_count"] = 0
            node["ucp_version"] = extract_version(profile)
            print(f"  [{domain}] Verified successfully")
        else:
            # Failed verification
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

    # Write updated registry
    REGISTRY_PATH.write_text(json.dumps(nodes, indent=2) + "\n")
    print(f"\nDone. Registry updated.")


if __name__ == "__main__":
    verify_nodes()
