---
name: EDR cloudlab project
description: Sibling project to edr/ at /mnt/d/priv/code/edr-cloudlab — cloud dev host + Linux/Windows test lab for the EDR PoC, planned but not yet provisioned
type: project
originSessionId: 41838ce8-bbd2-4e23-85c0-b5b3a55ea93d
---
Sibling project to the EDR repo, at `/mnt/d/priv/code/edr-cloudlab/`. Goal: move
Claude Code off the local WSL2 box onto a cloud dev host, plus disposable
Linux + Windows lab VMs the dev host can deploy to and reset in minutes. User
keeps current VS Code + mobile (`/remote-control`) workflow unchanged.

**Why:** Local Claude Code runs are CPU/RAM-heavy, require the machine to stay
on, and risk damaging the user's setup since the EDR work involves kernel
drivers and eBPF.

**How to apply:**
- All planning docs live under [edr-cloudlab/docs/](/mnt/d/priv/code/edr-cloudlab/docs/) — research, architecture, 6-phase build plan, migration paths. Read them before re-deriving the design.
- Recommended stack (updated 2026-05-08): Infomaniak Public Cloud single-provider (OpenStack-based) — `a8-ram32-disk80-perf2` dev host, `a2-ram4-disk80-perf1` Linux lab, `a4-ram16-disk80-perf2` Windows lab; Tailscale fabric; Terraform (openstack provider) + Packer (openstack builder) + Ansible IaC. Single OpenStack project (`edr`) with separate Neutron tenant networks per VM; isolation enforced by Tailscale ACLs and credentials-stay-on-laptop, not by project boundaries.
- Provider switched from prior Hetzner+Azure split to Infomaniak because Infomaniak supports Windows VMs natively; eliminates the dual-provider complexity.
- 2FA via TOTP (not YubiKey) — see [TOTP over YubiKey](feedback_no_yubikey.md).
- Three open questions to verify before provisioning: (1) exact Windows Server image name in Glance catalog, (2) nested-virt support on Windows flavor for Hyper-V kernel debugging, (3) whether `nova shelve` stops compute billing.
- Key insight that shaped the design: Claude Code's Remote Control is outbound-HTTPS only, so the cloud host needs zero public ingress.
- Status: `infra/` scaffolding empty (Terraform / Packer / Ansible subdirs with .gitkeep). Phase 0 not yet started.
- When suggesting next steps, point to [edr-cloudlab/docs/03-build-plan.md](/mnt/d/priv/code/edr-cloudlab/docs/03-build-plan.md) phases rather than re-planning.
