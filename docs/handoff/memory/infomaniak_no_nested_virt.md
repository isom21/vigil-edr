---
name: Infomaniak Public Cloud — no nested virtualization
description: Infomaniak Public Cloud (OpenStack, dc4-a tested 2026-05-08) does not expose VT-x/VMX or AMD-V to guests; nested KVM/Hyper-V will not work
type: project
originSessionId: 41838ce8-bbd2-4e23-85c0-b5b3a55ea93d
---
Infomaniak Public Cloud does **not** expose CPU virtualization extensions to
guest VMs. Verified empirically 2026-05-08 in region `dc4-a` on flavor
`a1-ram2-disk20-perf1`: `kvm-ok` reported "Your CPU does not support KVM
extensions". `/proc/cpuinfo` had no `vmx`/`svm` flag.

**Why it matters:** Any design that wants to run Hyper-V, KVM-on-KVM, nested
ESXi, or use Hyper-V isolation features (Credential Guard, HVCI as a *guest*)
on Infomaniak will fail. Most cloud providers behave this way; only AWS
`*.metal` and Azure Dv3+ expose nested virt.

**How to apply:** When Windows kernel debugging or hypervisor-guest
experiments come up on Infomaniak, plan around it: use kdnet over the network
instead of Hyper-V nested debugging, treat the cloud VM itself as the
snap/revert unit (rebuild from Glance image), and don't propose Hyper-V
isolation features. If a future workload truly needs nested virt, plan for a
different provider (bare-metal Hetzner, AWS metal) for that one role.
