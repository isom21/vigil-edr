# Security policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in Vigil,
please report it privately rather than opening a public issue.

**Preferred channel**: GitHub's private vulnerability reporting via
the repo's *Security* tab → *Report a vulnerability*.

**Email fallback**: `isom21@protonmail.com`, encrypted to the PGP
key below.

PGP key fingerprint:

```
E0D6 1F18 2769 7B07 F92C  B931 13F9 0FAE 063B A39D
```

The full ASCII-armored public key is at
[`docs/security.asc`](docs/security.asc). To import and verify:

```bash
# From a fresh checkout:
gpg --import docs/security.asc

# Verify the fingerprint matches what's printed above:
gpg --fingerprint isom21@protonmail.com

# Encrypt a report:
gpg --armor --encrypt --recipient isom21@protonmail.com report.txt
```

If you trust the in-repo file, that's enough. As an out-of-band
confirmation, the same key is also retrievable through ProtonMail's
WKD (`gpg --auto-key-locate wkd --locate-keys
isom21@protonmail.com`); cross-check the fingerprint matches what's
printed above before encrypting.

### What to include

* Affected component (`agent-linux` / `agent-windows` /
  `kernel-windows` / `backend` / `frontend`).
* Affected version (commit SHA or release tag).
* Reproduction steps.
* Impact (what an attacker can do).
* Whether you've already seen this exploited in the wild.

Acknowledgement target is 3 business days; fixes ship within 30 days
for critical, 90 days for non-critical.

## Disclosure timeline

A standard 90-day timeline:

1. Day 0: report received, triage starts.
2. Day 0–7: severity assessment, CVE reservation if appropriate.
3. Day 7–60: fix developed and tested.
4. Day 60–80: patched release shipped.
5. Day 90: public disclosure (CVE published, advisory in
   `docs/advisories/`).

Reporters who follow the timeline get credit in the advisory unless
they prefer to remain anonymous.

## Out of scope

The following are documented behaviour, not vulnerabilities:

* Same-box root can stop the agent via `systemctl stop` /
  `sc.exe stop`. By design — see
  [`docs/threat-model.md`](docs/threat-model.md). Agents enforce
  self-protection against silent kill / ptrace / debug / unlink, but
  the OS service-control plane remains administratively
  authoritative.
* `bcdedit /set testsigning on` weakens Windows driver signing — only
  required for the test-cert build path. Production deployments use
  WHQL-attested or cross-signed `vigil.sys`.
* Default `VIGIL_RL_*` rate limits are tuned for moderate fleets.
  Operators who don't tune for very large fleets can degrade ingest
  throughput. Operator responsibility, not a CVE-class bug.

## Hall of fame

(Empty until first real report.)
