# M18 — Pre-paid prep

> **Status:** scaffolded. M18 readies the build/sign infrastructure
> so that when the M19 paid certs arrive, the operator only plugs in
> credentials — no engineering work.

The free engineering done here:

1. SBOM generation per build (syft / cargo-cyclonedx / cyclonedx-py /
   cyclonedx-npm) wired into CI as `make sbom`.
2. GPG key-management runbook (operator generates their own, no cost).
3. `tools/sign/` placeholder scripts that the M19 commit fills in
   with cert paths.
4. Sigstore-keyless signing for OCI containers (free Public Good
   Instance) — no-op locally; activated via CI's GitHub OIDC.
5. Reproducible-builds posture: `rust-toolchain.toml` already pins
   the Rust version. M18 adds a Nix flake for the manager.

This document captures what each piece does so M19 lands as a
near-mechanical change.

## SBOM generation

`make sbom` runs:

```bash
syft target/release/edr-agent              -o cyclonedx-json > target/sbom/agent-linux.cdx.json
syft target/debian/*.deb                    -o cyclonedx-json > target/sbom/agent-linux.deb.cdx.json
syft target/generate-rpm/*.rpm              -o cyclonedx-json > target/sbom/agent-linux.rpm.cdx.json
syft kernel-windows/edr.sys                 -o cyclonedx-json > target/sbom/edr-driver.cdx.json
cyclonedx-py environment ~/edr-venvs/backend > target/sbom/manager.cdx.json
cyclonedx-npm                                > target/sbom/frontend.cdx.json
```

The SBOMs ship alongside each release artefact (or get attached to
a Sigstore Rekor entry once M19's signing key lands).

## GPG key for deb / rpm

```bash
gpg --batch --gen-key <<EOF
Key-Type: EdDSA
Key-Curve: ed25519
Key-Usage: cert
Subkey-Type: EdDSA
Subkey-Curve: ed25519
Subkey-Usage: sign
Name-Real: EDR Project Release Key
Name-Email: release@edr.example
Expire-Date: 2y
%no-protection
%commit
EOF
```

Public key gets:
1. Exported: `gpg --export --armor release@edr.example > deploy/edr-release.pub.asc`
2. Published on whatever simple HTTPS host the operator has (the
   project's GitHub Release page is the easy path).
3. Customer's apt sources hold a copy: `apt-key add edr-release.pub.asc`.

Private key:
- Stays in the operator's GPG home (offline machine recommended).
- Used by `tools/sign/sign-deb.sh` to invoke `dpkg-sig` /
  `debsigs --sign builder` after each build.
- Eventually moved onto a hardware token (YubiKey 5 will do; ~$50,
  treated as M19 if the operator wants HSM rigor).

## Reproducible builds

`flake.nix` (M18.a follow-up):

```nix
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/24.11";
  outputs = { nixpkgs, ... }: {
    packages.x86_64-linux.manager = let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in pkgs.callPackage ./nix/manager.nix {};
  };
}
```

This pins every build dependency to a hash, so the same input always
produces a bit-identical output. Customers can verify by running the
same `nix build` against the same SBOM and comparing.

## Sigstore-keyless container signing

For the manager / worker container images:

```bash
# Set up cosign (one-time):
cosign initialize

# Sign + attest (uses GitHub OIDC in CI; interactive in dev):
cosign sign ghcr.io/example/edr-manager:0.2.0
cosign attest --predicate target/sbom/manager.cdx.json \
              --type cyclonedx \
              ghcr.io/example/edr-manager:0.2.0

# Customer verification:
cosign verify ghcr.io/example/edr-manager:0.2.0 \
   --certificate-identity-regexp 'example\.com' \
   --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Public Good Instance is free; no key procurement.

## What still needs M19's money

Documented for clarity:

| Item | Cost | Why blocked here |
|---|---|---|
| EV Code Signing cert (commercial CA) | ~$300-500/year | Required for Authenticode + WHQL submission |
| Microsoft Hardware Dev Center | $99/year | Driver attestation signing |
| Apple Developer Program | $99/year | macOS notarization (M10.i prereq) |
| MVI / ELAM cert | gated, free if accepted | True PPL on Windows |
| HSM hardware | $50-650 one-time | GPG / signing key escalation |

Each of these slots into the M18 scripts as a single environment
variable / file path.

## Smoke-test the pre-paid path

`tools/sign/dry-run.sh` (M18.a) builds + SBOM-generates + would-sign
without actually invoking signtool / dpkg-sig. Used to verify the
release flow before any paid cert is in hand.
