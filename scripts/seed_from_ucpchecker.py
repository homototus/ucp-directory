"""Seed registry.json with domains from UCPChecker.com directory.

Fetches verified merchant domains from UCPChecker's public directory,
then adds them to registry.json with status "pending" for our crawler
to verify independently.

UCPChecker data is CC-BY 4.0 licensed. We only extract domain names
and verify them ourselves — no data is copied verbatim.

Usage:
    python scripts/seed_from_ucpchecker.py [--max-pages N] [--dry-run]
"""

import json
import re
import sys
import time
from pathlib import Path

import requests

REGISTRY_PATH = Path(__file__).parent.parent / "registry.json"
UCPCHECKER_URL = "https://ucpchecker.com/directory"
MAX_PAGES = 65
DELAY_BETWEEN_REQUESTS = 2  # seconds (well under 100 req/hour limit)

USER_AGENT = (
    "Mozilla/5.0 (compatible; UCP-Directory-Seeder/1.0; "
    "+https://hungry-ucp.dev)"
)

# Match domains from UCPChecker's /status/{domain} links
MERCHANT_DOMAIN_RE = re.compile(
    r'/status/([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})'
)


def fetch_page(page: int) -> str | None:
    """Fetch a single directory page from UCPChecker."""
    url = f"{UCPCHECKER_URL}?page={page}"
    try:
        resp = requests.get(
            url,
            timeout=15,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 200:
            return resp.text
        print(f"  Page {page}: HTTP {resp.status_code}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"  Page {page}: {e}", file=sys.stderr)
        return None


def extract_domains(html: str) -> set[str]:
    """Extract merchant domains from a UCPChecker directory page."""
    domains = set()

    # Try /check/domain pattern first (most reliable)
    for match in MERCHANT_DOMAIN_RE.finditer(html):
        domain = match.group(1).lower().strip(".")
        if domain and "." in domain:
            domains.add(domain)

    return domains


def load_registry() -> list[dict]:
    """Load existing registry.json."""
    if REGISTRY_PATH.exists():
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return []


def save_registry(nodes: list[dict]) -> None:
    """Save registry.json."""
    REGISTRY_PATH.write_text(
        json.dumps(nodes, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Seed registry from UCPChecker")
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Load existing domains
    registry = load_registry()
    existing = {node["domain"] for node in registry}
    print(f"Existing registry: {len(existing)} domains\n")

    # Fetch domains from UCPChecker
    all_domains: set[str] = set()
    for page in range(1, args.max_pages + 1):
        print(f"Fetching page {page}/{args.max_pages}...")
        html = fetch_page(page)
        if html is None:
            print(f"  Stopping at page {page} (fetch failed)")
            break

        domains = extract_domains(html)
        if not domains:
            print(f"  No domains found on page {page}, stopping")
            break

        new_on_page = domains - all_domains - existing
        all_domains.update(domains)
        print(f"  Found {len(domains)} domains ({len(new_on_page)} new)")

        time.sleep(DELAY_BETWEEN_REQUESTS)

    # Filter out already-registered domains
    new_domains = sorted(all_domains - existing)
    print(f"\nTotal discovered: {len(all_domains)}")
    print(f"Already registered: {len(all_domains & existing)}")
    print(f"New to add: {len(new_domains)}")

    if args.dry_run:
        print("\n[DRY RUN] Would add:")
        for d in new_domains[:20]:
            print(f"  {d}")
        if len(new_domains) > 20:
            print(f"  ... and {len(new_domains) - 20} more")
        return

    if not new_domains:
        print("\nNo new domains to add.")
        return

    # Add new domains to registry
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")

    for domain in new_domains:
        registry.append({
            "domain": domain,
            "name": domain,
            "description": "Discovered via UCPChecker.com",
            "url": f"https://{domain}",
            "status": "pending",
            "capabilities": [],
            "registered": now,
            "last_checked": None,
            "last_verified": None,
            "failure_count": 0,
            "ucp_version": None,
        })

    save_registry(registry)
    print(f"\nAdded {len(new_domains)} domains to registry.json")
    print("Run `python scripts/verify.py` to verify them.")


if __name__ == "__main__":
    main()
