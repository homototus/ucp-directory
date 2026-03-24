# UCP Directory

An open-source, community-maintained registry of live [Universal Commerce Protocol](https://ucp.dev) nodes.

UCP is an open standard enabling interoperability between commerce platforms, AI agents, and businesses. While the protocol includes a decentralized discovery mechanism (`/.well-known/ucp`), no central directory of participating nodes exists. This project provides a public registry with automated health checks.

## How It Works

- **Registry**: [`registry.json`](registry.json) lists all known UCP nodes with their current status
- **Verification**: A GitHub Action checks each node's `/.well-known/ucp` endpoint every 6 hours
- **Status**: Nodes are marked as `verified`, `pending`, or `offline` based on crawler results
- **Browsing**: Visit [hungry-ucp.dev](https://hungry-ucp.dev) to explore nodes

## Node Statuses

| Status | Meaning |
|--------|---------|
| `verified` | `/.well-known/ucp` responds with a valid UCP profile |
| `pending` | Registered but not yet serving a UCP profile |
| `offline` | A previously verified node that has failed 3 consecutive health checks |

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

A CORS-enabled version for client-side use is also available:

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

Contributions are welcome. To add or update a node, submit a pull request against `registry.json`.

## Disclaimer

This directory is a community-maintained resource. A listing does not imply endorsement by the project maintainers or the UCP specification authors. Please conduct your own due diligence before transacting with any listed entity.

## License

[MIT](LICENSE)
