---
name: User role and preferences
description: User is a cyber security engineer building an EDR; deep-stack comfort, prefers production-realistic over PoC shortcuts.
type: user
originSessionId: 04069394-44f9-41e9-9017-3a82415636ec
---
Cyber security engineer building an EDR end-to-end (agent + manager).

**Technical depth:** Comfortable choosing the harder/deeper option across the stack — kernel drivers on Windows, eBPF on Linux, Kafka + Flink for streaming, mTLS with internal CA, ECS-aligned event schema. When given choices between "PoC shortcut" and "production-realistic", consistently picked production-realistic.

**How to apply:**
- Don't propose simplifications that sacrifice production-realism unless flagged as a real risk to the schedule.
- Don't over-explain foundational concepts (ETW, eBPF, Kafka, mTLS, etc.) — the user knows these.
- Do flag tradeoffs honestly when the deeper choice has real cost (e.g., Windows driver dev iteration speed, Flink complexity).
- The user works on Windows-target agents in WSL2 (Linux 6.6, /mnt/d/priv/code/). Assume WSL for backend dev; Windows VM (Hyper-V/VMware) for kernel driver dev.
