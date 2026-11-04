---
title: "MCP Server"
linkTitle: "MCP Server"
type: docs
weight: 9
description: >
  Ask BOMHort questions from an AI agent — the read-only Model Context Protocol tool surface.
---

{{% pageinfo %}}
The MCP server ships with BOMHort 0.8.0 and is **read-only**. It can answer
questions about projects, packages, vulnerabilities and SBOMs. It cannot
upload an SBOM, write a VEX statement or change a policy, and it never calls
a language model itself.
{{% /pageinfo %}}

## What it is

`mcp-server` is the fifth BOMHort binary. It speaks the
[Model Context Protocol](https://modelcontextprotocol.io) so an MCP-capable
client — Claude Desktop, an IDE agent, a custom tool runner — can query a
BOMHort instance without anyone writing a REST integration first.

It is a **consumer of the REST API**, not a second reader of the database. It
holds no ClickHouse credentials. Everything it can tell an agent is something
`GET /api/v1/...` already returns, which is the point: the MCP server is the
first external consumer of the API contract that 1.0 freezes, and a consumer
that reached around the contract would not exercise it.

## The five tools

| Tool | Answers | Backed by |
|------|---------|-----------|
| `list_projects` | "What does this instance know about?" | `GET /api/v1/projects` |
| `get_project` | "What is the state of *payment-service*?" | `GET /api/v1/projects/{name}` (+ `/sboms`) |
| `search_packages` | "Who ships log4j-core, and in which versions?" | `GET /api/v1/packages/search` |
| `list_vulnerabilities` | "What is open, instance-wide or per project? Per cluster, namespace, parent or tag?" | `GET /api/v1/vulnerabilities`, `GET /api/v1/projects/{name}/vulnerabilities` |
| `get_sbom` | "What is in this document?" | `GET /api/v1/sboms/{id}/detail` (+ `/vulnerabilities`) |

All five are annotated `readOnlyHint`, `idempotentHint` and closed-world, so a
client can call them without asking the user to confirm each one.

Two semantics are stated in the server's `instructions` because a model cannot
infer them from the schemas and otherwise gets them wrong:

* **Project counts are de-duplicated across versions.** A package present in
  ten versions of a project counts once, and so does a finding. Summing
  per-version numbers to get a project total produces a wrong, larger number.
* **Suppressed findings are returned, not hidden.** A finding that VEX marks
  `not_affected` appears in the list with its `vex_status` set. It is
  documented as not exploitable — not ignored, and not absent.

### Paging and filters

`list_projects`, `search_packages` and the instance-wide
`list_vulnerabilities` page server-side (`page`, `page_size`, default 25, max
500). Scoped to a project, `list_vulnerabilities` pages *in the MCP server*,
because the project endpoint answers with the project's distinct findings in
one response — de-duplication across versions cannot be done a page at a time.

`severity` therefore only works together with `project`. Asking for
`severity: CRITICAL` on the instance-wide listing returns an error rather than
a number that only describes one page.

`scope` (`root`, `direct`, `transitive`, `unknown`) has no such restriction:
the API filters it server-side on both endpoints, so the total stays honest.
Every returned finding carries `dependency_scope` and `dependency_depth`, which
lets an agent answer "which of these CVEs are in libraries we depend on
directly?" without reconstructing the dependency tree.

## Running it on a laptop (stdio)

stdio is the default and needs no port, no token and no origin list, because
nothing is listening. The client starts the binary and talks to it over the
pipe.

```jsonc
// Claude Desktop: claude_desktop_config.json
{
  "mcpServers": {
    "bomhort": {
      "command": "/usr/local/bin/mcp-server",
      "env": {
        "MCP_API_BASE_URL": "https://bomhort.example.com",
        "MCP_API_KEY": "your-api-key"        // only if the API has AUTH_ENABLED
      }
    }
  }
}
```

With the container image instead of a local binary:

```jsonc
{
  "mcpServers": {
    "bomhort": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "MCP_API_BASE_URL=https://bomhort.example.com",
        "ghcr.io/seebom-labs/bomhort/mcp-server:0.8.0"
      ]
    }
  }
}
```

From a checkout: `make mcp`.

`MCP_API_BASE_URL` accepts the URL as copied from a browser — a trailing
`/api/v1` is stripped rather than doubled.

## Running it in the cluster (Streamable HTTP)

Only do this if agents outside your machine need to reach the instance. The
HTTP transport is a **remote tool-execution endpoint**, and the chart treats
it accordingly:

```yaml
mcp:
  enabled: true
  transport: http
  httpToken: ""                                # or existingSecret
  allowedOrigins:
    - https://agent.example.com                # see "Which origins to allow"
```

`helm template` **fails** — not warns — if `httpToken` is missing, if
`allowedOrigins` is empty, or if it contains `*`. The binary makes the same
checks at startup. There is no flag to turn this off:

* An unauthenticated MCP endpoint is remote tool execution for anyone who can
  reach the port.
* `*` re-opens the cross-site hole that CVE-2026-33252 described — a
  Streamable HTTP transport accepting cross-site `POST`s without validating
  `Origin`. A browser page a victim happens to have open must not be able to
  drive the server.

A CLI client sends no `Origin` header at all and is unaffected by the list;
the list exists to stop browsers. Credentials are accepted as
`Authorization: Bearer <token>` or `X-API-Key`, compared in constant time.

When `apiGateway.auth.enabled` is set, the MCP server automatically reads the
release's `SERVICE_TOKEN` from the same Secret — one token, one place.

### Which origins to allow

`allowedOrigins` is not the address of the MCP server. It lists the web pages
that may call it from a browser. An origin is scheme plus host (plus port),
never a path.

* **Only CLI/desktop agents** (Copilot CLI, Claude Code, VS Code, Claude
  Desktop): they send no `Origin`, so the list never matches them. It still
  must not be empty; use a name that cannot resolve, which states the intent:

  ```yaml
  mcp:
    allowedOrigins: ["https://no-browser-clients.invalid"]
  ```

* **A browser-based agent**: list its exact origin, e.g.
  `https://agent.example.com`.
* Do **not** list the origin of BOMHort's own UI when the MCP server is served
  under the same host (see below): every page of the UI would then be allowed
  to drive it.

### Exposing it

The chart creates a `ClusterIP` Service `<release>-mcp-server` (port 80) and
nothing else — neither the chart's Ingress nor its UI proxy route to it. Add
your own route. The server answers on any path, so either a dedicated host or a
path on the existing host works, without a rewrite.

Generate the token and keep it in a Secret:

```sh
kubectl create secret generic bomhort-mcp \
  --from-literal=MCP_HTTP_TOKEN="$(openssl rand -hex 32)"
```

```yaml
mcp:
  enabled: true
  transport: http
  allowedOrigins: ["https://no-browser-clients.invalid"]
  existingSecret:
    enabled: true
    secretName: bomhort-mcp
    httpTokenKey: MCP_HTTP_TOKEN
```

A path on the existing host (`https://bomhort.example.com/mcp`) — no new DNS
name or certificate. The longest prefix wins, so `/` keeps going to the UI:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: bomhort-mcp
spec:
  parentRefs: [{ name: <your-gateway> }]
  hostnames: ["bomhort.example.com"]
  rules:
    - matches: [{ path: { type: PathPrefix, value: /mcp } }]
      backendRefs: [{ name: <release>-mcp-server, port: 80 }]
      timeouts: { request: 3600s }
```

For a dedicated host (`https://mcp.bomhort.example.com`), drop `matches` and
change `hostnames`. Either way:

* Route **directly** to the MCP Service, not through the UI's nginx — that
  proxy injects its own `Authorization` header on read requests.
* Streamable HTTP keeps responses open as server-sent events. Raise the request
  timeout (gateway defaults are often 15–30 s) and do not buffer responses.

Check it — `401` without a token, `200` and an `event: message` with one:

```sh
curl -s -X POST https://bomhort.example.com/mcp \
  -H "Authorization: Bearer $BOMHORT_MCP_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

### Connecting an agent

Each client needs the URL and the token. Keep the token out of files that are
committed.

Copilot CLI — `~/.copilot/mcp-config.json`, then check with `/mcp`:

```json
{
  "mcpServers": {
    "bomhort": {
      "type": "http",
      "url": "https://bomhort.example.com/mcp",
      "headers": { "Authorization": "Bearer <token>" },
      "tools": ["*"]
    }
  }
}
```

VS Code — `.vscode/mcp.json`; the token is prompted for once and not written to
the file:

```jsonc
{
  "inputs": [
    { "type": "promptString", "id": "bomhort-token", "password": true, "description": "BOMHort MCP token" }
  ],
  "servers": {
    "bomhort": {
      "type": "http",
      "url": "https://bomhort.example.com/mcp",
      "headers": { "Authorization": "Bearer ${input:bomhort-token}" }
    }
  }
}
```

Claude Code:

```sh
claude mcp add --transport http bomhort https://bomhort.example.com/mcp \
  --header "Authorization: Bearer $BOMHORT_MCP_TOKEN"
```

A single user against a public instance does not need any of this: the
[stdio setup](#running-it-on-a-laptop-stdio) with `MCP_API_BASE_URL` pointing
at the instance needs no route, no token and no origin list.

## Configuration reference

| Environment variable | Helm value | Default | Meaning |
|----------------------|-----------|---------|---------|
| `MCP_TRANSPORT` | `mcp.transport` | `stdio` | `stdio` or `http` |
| `MCP_HTTP_ADDR` | `mcp.port` | `127.0.0.1:8081` | Listen address (http only) |
| `MCP_HTTP_TOKEN` | `mcp.httpToken` | — | Inbound bearer token, **required** for http |
| `MCP_ALLOWED_ORIGINS` | `mcp.allowedOrigins` | — | Explicit Origin allow-list, **required** for http |
| `MCP_API_BASE_URL` | `mcp.apiBaseURL` | `http://localhost:8080` | Where the API gateway is |
| `MCP_SERVICE_TOKEN` | `mcp.serviceToken` | `SERVICE_TOKEN` | Credential sent *to* the API |
| `MCP_API_KEY` | `mcp.apiKey` | first `API_KEYS` entry | Credential sent *to* the API |
| `MCP_REQUEST_TIMEOUT_SECONDS` | `mcp.requestTimeoutSeconds` | `30` | Per-upstream-request timeout |

## Not in scope

* **Write tools.** No upload, no VEX authoring, no policy changes. BOMHort's
  frontend is public and its policies are config files; there is no mutation
  this server could legitimately offer. Write tools are additive and can be
  added after 1.0 without breaking anything.
* **LLM calls.** BOMHort never calls a model. The MCP server is a transport;
  automated reasoning over findings lives in the
  [VEXViper](https://github.com/seebom-labs/VEXViper) sidecar.
* **A second data path.** If a question cannot be answered by the REST API, it
  cannot be answered by a tool here either. That is a feature request against
  the API, and the right place to make one.

