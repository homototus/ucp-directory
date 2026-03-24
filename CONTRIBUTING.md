# Contributing

## Registering a Node

The simplest way to add your UCP node:

1. Open a [registration issue](../../issues/new?template=register.yml)
2. A maintainer will review your submission
3. Once approved, the automated crawler verifies your `/.well-known/ucp` endpoint every 6 hours

## Review Criteria

Submissions are reviewed for:

- **Domain validity**: Must be a real, publicly accessible domain
- **Business legitimacy**: Website exists and is operational
- **Intent to serve UCP**: Domain should serve (or plan to serve) a UCP profile at `/.well-known/ucp`

## Manual Registration via PR

Edit `registry.json` directly and submit a pull request. Each entry must include:

- `domain` — the domain hosting `/.well-known/ucp`
- `name` — business name
- `description` — brief description of what the business does
- `url` — main website URL (must be `https://`)
- `status` — set to `"pending"` for new entries
- `capabilities` — set to `[]`
- `registered` — ISO 8601 UTC timestamp
- `last_checked`, `last_verified` — set to `null`
- `failure_count` — set to `0`
- `ucp_version` — set to `null`

## Removal Requests

To remove a node, open an issue with the label `security` or submit a PR removing the entry from `registry.json`. Removal requests are processed within 48 hours.

## Reporting Abuse

If a listed node is fraudulent or harmful, open an issue with the `security` label. Include the domain and a description of the concern.

## Local Development

```bash
pip install -r scripts/requirements.txt
python scripts/verify.py
```

Requires Python 3.12+.

## Code Contributions

For changes to the crawler, site, or workflow:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request against `main`

All workflow and registry changes require maintainer review (see CODEOWNERS).
