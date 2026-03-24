# UCP Directory

A community-maintained tracker of live [Universal Commerce Protocol](https://ucp.dev) nodes.

UCP is an open standard enabling interoperability between commerce platforms, AI agents, and businesses. The protocol defines a decentralized discovery mechanism via `/.well-known/ucp` endpoints — but there is no central place to find participating merchants.

This project fills that gap: a public, transparent registry of UCP nodes with automated verification.

## How It Works

- **Registry**: [`registry.json`](registry.json) lists all known UCP nodes with their current status
- **Verification**: A GitHub Action crawls each node's `/.well-known/ucp` endpoint every 6 hours
- **Status**: Nodes are marked as `verified`, `pending`, or `offline` based on crawler results
- **Browsing**: Visit [hungry-ucp.dev](https://hungry-ucp.dev) to explore nodes

## Node Statuses

| Status | Meaning |
|--------|---------|
| `verified` | `/.well-known/ucp` responds with a valid UCP profile |
| `pending` | Registered but not yet serving a UCP profile |
| `offline` | Was verified, but failed 3 consecutive checks |

## Register Your Node

1. Open a [registration issue](../../issues/new?template=register.yml)
2. Fill in your domain, business name, and description
3. A maintainer will review and add your node to the registry
4. The crawler will automatically verify your `/.well-known/ucp` endpoint

## API

The registry is a plain JSON file. Fetch it directly:

```
https://raw.githubusercontent.com/homototus/ucp-directory/main/registry.json
```

GitHub Pages serves it with CORS headers, so client-side fetching works too:

```
https://hungry-ucp.dev/registry.json
```

## Schema

Each node in `registry.json`:

```json
{
  "domain": "example.com",
  "name": "Example Store",
  "description": "What this business sells",
  "url": "https://example.com",
  "status": "pending",
  "capabilities": [],
  "registered": "2026-03-24T00:00:00Z",
  "last_checked": null,
  "last_verified": null,
  "failure_count": 0,
  "ucp_version": null
}
```

## Contributing

PRs welcome. To add a node manually, edit `registry.json` and submit a PR. The CI will validate the format.

## Disclaimer

Listing in this directory does not constitute endorsement. Verify merchants independently before transacting. This is a community project and is not affiliated with the UCP specification authors.

## License

[MIT](LICENSE)
