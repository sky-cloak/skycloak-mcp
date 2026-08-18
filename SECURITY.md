# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@skycloak.io** rather than opening a public issue.

Include what you did, what you expected, and what happened instead. A proof of concept helps but is not required to
start the conversation. If you would like a PGP key, ask and we will send one.

We aim to acknowledge a report within two business days and to keep you updated as we work on it. We will tell you
when a fix ships, and we are glad to credit you in the changelog unless you would rather stay anonymous.

Please give us a reasonable window to release a fix before disclosing publicly.

## Scope

This repository is the MCP server. Issues in the hosted endpoint at `https://mcp.skycloak.io`, the Skycloak platform
API, or the dashboard belong to the same address.

Things worth knowing before you report:

- The server holds no session state. Every request carries its own credential and acts only as that credential's
  workspace.
- The hosted server is write-capable. What a caller can change is bounded by the scopes on their key and their
  workspace role, not by the tool list.
- Access tokens, `Authorization` headers and minted API keys are never logged.
- `get_cluster_credentials` returns Keycloak admin credentials and is deliberately opt-in, behind a scope that is not
  granted by default.

## Supported versions

The hosted server tracks the latest release. For the binary, only the most recent release receives fixes.
