# M10.b — Linux DNS observation design

> **Status:** wire schema, capture path, and DNS block list shipped
> (Phase 2 #2.12). Sigma rules now reference `dns.name` directly; the
> `dns_block_domains` BPF map enforces operator-issued block rules
> in the kernel. The two complementary capture paths (M10.b-bpf and
> M10.b-resolved) are both in production — the operator chooses one
> via the agent config based on the host's resolver shape.

## Wire schema (this commit)

`DnsEvent` payload variant on `EndpointEvent.payload` (tag 27):

```proto
message DnsEvent {
  ProcessKey process = 1;
  string name = 2;            // queried hostname (FQDN, no trailing dot)
  uint32 qtype = 3;            // 1=A, 28=AAAA, 5=CNAME, ...
  uint32 rcode = 4;            // 0=NoError, 3=NXDOMAIN, ...
  repeated string answers = 5; // resolved IPs / CNAMEs, best-effort
  string resolver = 6;         // resolver IP the query was sent to
  DnsAction action = 7;        // QUERY | ANSWER | BLOCKED
}
```

ECS mapping (in `app.services.normalizer`):
  `dns.question.name` ← `name`
  `dns.question.type` ← `qtype` (translated to ECS string: "A", "AAAA", ...)
  `dns.response_code` ← `rcode` (translated: "NoError", "NXDomain", ...)
  `dns.resolved_ip` ← `answers` (filtered to A/AAAA values)
  `network.transport` ← "udp" or "tcp" depending on path
  `event.category` ← ["network"]
  `event.action` ← "dns_query" / "dns_answer" / "dns_blocked"

## Capture paths

### M10.b-bpf — kprobe on udp_sendmsg / udp_recvmsg

**Goal**: zero-copy DNS observability, works on every Linux endpoint
regardless of which resolver is configured.

**Sketch** (`agent-linux/ebpf/vigil.bpf.c` extension):

```c
SEC("kprobe/udp_sendmsg")
int handle_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    // Filter to dport 53.
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (bpf_ntohs(dport) != 53) return 0;
    // Read up to 200 bytes of msg->msg_iter into a per-cpu scratch.
    // Parse the DNS header (12 bytes) + first question name in
    // userspace via the ringbuf. Cap to AVOID parsing in BPF.
    ...
}

SEC("kprobe/udp_recvmsg")
int handle_udp_recvmsg(struct pt_regs *ctx) {
    // Tag the response by skb->sk == query's sk.
    // Captured payload: header + first answer RR.
    ...
}
```

**Wire**: agent userspace ring drainer parses the DNS frame
(`agent-linux/src/dns_parser.rs`, M10.b-bpf follow-up) and emits
DnsEvent with action=QUERY for sendmsg, action=ANSWER for recvmsg.

**Caveats**:
- DNS over TCP (long answers, AXFR) needs a parallel kprobe on
  `tcp_sendmsg` filtered to dport 53.
- DoH (DNS-over-HTTPS) is invisible to this — TLS-encrypted at the
  kernel layer. Documented as out of scope alongside the existing
  plaintext-before-TLS gap.
- DoT (DNS-over-TLS, port 853) similarly invisible. Detection signal
  here is the *connection itself* to a known DoT resolver, not the
  query content.

### M10.b-resolved — journald subscription to systemd-resolved

**Goal**: cheap fallback for hosts running systemd-resolved (~70% of
modern Linux distros). Operator-side configuration: enable
`DNSSEC=allow-downgrade` and `DNSOverTLS=opportunistic` to maximise
both observability and resolver behaviour.

**Sketch** (`agent-linux/src/dns_watcher.rs`, M10.b-resolved follow-up):

```rust
// Subscribe to journald via libsystemd-rs's journal::reader API.
// Filter to messages where _SYSTEMD_UNIT == "systemd-resolved.service"
// and MESSAGE matches the "Looking up RR" / "Looked up RR" patterns.
// Parse the structured field set:
//   QUERY=, RESULT=, RCODE=
// Emit DnsEvent with the appropriate action.
```

This is more fragile than BPF (depends on systemd-resolved log format,
which has changed across systemd versions) but ships in a single Rust
file with no kernel changes.

### Comparison

| Path | Coverage | Cost | Failure mode |
|---|---|---|---|
| BPF kprobe | every UDP/53 + TCP/53 query, regardless of resolver | kernel CPU per packet, ~150 LoC C + Rust parser | DoH/DoT invisible |
| Resolved journal | only hosts with systemd-resolved enabled | trivial, ~80 LoC Rust | Misses Glibc-cache resolutions, alpine/musl, custom resolvers |

Production deployments ship **both**. BPF gets the heavy work; the
resolved tail is a corroboration source + works on hosts where BPF
LSM isn't available (older kernels).

## DNS-specific detection rules to ship in M11.b

Once DnsEvent flows, the curated Sigma pack picks up:

* DNS to known C2 infrastructure (IOC list match against `name`).
* High-entropy DNS labels (DGA detection — Shannon entropy of
  `name` segments above threshold).
* DNS over non-standard port (UDP/53 is normal; UDP/5353 is mDNS;
  any other dport with DNS magic bytes is an IOC).
* Spike in NXDOMAIN responses from a host (DGA C2 pattern).
* Unusual qtype (TXT-heavy queries from a non-mail-server host).

Each rule is a YAML drop-in into `backend/sigma_rules/`; they don't
land in this commit since they need the BPF capture to be live for
end-to-end testing.

## Ordering

1. **This commit** (M10.b): wire schema + this design doc.
2. **M10.b-bpf**: kprobe + Rust parser + ringbuf event format.
3. **M10.b-resolved**: journald subscription as a parallel source.
4. **M10.b-rules**: Sigma rules consuming `dns.*` ECS fields.

Each is independent given the schema is now stable.
