# kubeshark-oss

An open-source fork of **Kubeshark 37.0** — the last release of the
Kubernetes traffic viewer where the full stack (agent, tapper, CLI, UI)
was published under the Apache License 2.0.

This project re-implements features that shipped in later, closed-source
Kubeshark versions, keeping the tool fully self-hosted with no license
gate and no required cloud connectivity. It is an independent,
unaffiliated fork. See [NOTICE](NOTICE) for provenance and
licensing.

## Why this fork

Upstream Kubeshark split its components and moved the hub, worker and
front-end binaries to a Business Source License with a server-side
license requirement (a time-boxed 403 gate that forces a sign-up). The
`37.0` release (Nov 2022) predates that split and is fully Apache-2.0.
This fork restores and extends that base.

## What's in it

Inherited from the 37.0 base (working as-is):

- Live traffic viewer with dissection for HTTP/1.x, HTTP/2, gRPC, AMQP,
  Kafka and Redis.
- Display filters (CEL-style), per-entry PCAP, request replay,
  OpenAPI (OAS) generation and traffic statistics.
- `basenine` (Lindb) as the entries store; in-cluster agent + tapper
  DaemonSet topology.
- The eBPF-based TLS tapper (`--tls` / `--servicemesh`) that hooks
  OpenSSL, Go `crypto/tls` and BoringSSL/Envoy for decrypted traffic.

Being added (milestones below):

- **L4 visibility** — raw TCP flows appear as entries (5-tuple,
  direction, bytes, latency) and the capture BPF filter's hardcoded
  `port not 443` exclusion becomes opt-out, so TLS front-door legs are
  captured.
- **Workload Dependency Map** — the service map edges now carry
  per-dependency KPIs: average round-trip latency and cumulative bytes
  in/out alongside the request count, shown in an edge hover tooltip.
- **TLSX handshake dissection** — SNI, ALPN, cipher suites and TLS
  version parsed from the handshake even when the payload stays
  encrypted.

## Roadmap

- **M1** — L4 raw-TCP entries, `:443` capture fix, Workload Dependency
  Map, TLSX handshake dissection, and live-verified TLS decryption
  (OpenSSL + Go; BoringSSL/Envoy best-effort).
- **M2** — raw UDP entries, cluster-wide PCAP/snapshots, additional
  dissectors (MySQL/PostgreSQL/MongoDB, WebSocket, ICMP), BoringSSL
  offset database for custom builds, an MCP server + AI skills,
  eBPF-default capture, and service-map extensions (namespace/workload
  node grouping, p95 latency, per-edge HTTP error counts).

## Building

The image is built from the [`Dockerfile`](Dockerfile). It compiles the
agent (with the eBPF TLS-tapper objects) and the React UI, then layers
the `basenine` binary and the prebuilt UI site.

```
docker build -t kubeshark-oss:37.0-oss.0 .
```

The Go modules are per-directory (`tap/`, `agent/`, `cli/`, `shared/`,
`logger/`, `tap/api/`, `tap/dbgctl/`, and the `tap/extensions/*`
dissectors). Run tests from each module directory:

```
cd agent && go test ./...
cd tap   && go test ./...
```

## Relationship to upstream

- **Base:** [kubeshark/kubeshark](https://github.com/kubeshark/kubeshark)
  tag `37.0`, Apache-2.0.
- This is a re-implementation of post-37.0 features guided by public
  documentation; it does not include closed-source upstream code.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
