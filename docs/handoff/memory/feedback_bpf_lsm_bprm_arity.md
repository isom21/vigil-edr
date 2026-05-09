---
name: BPF LSM bprm_check_security must not declare a ret_in arg
description: BPF_PROG(handle_bprm_check, struct linux_binprm *bprm) — adding `int ret_in` and propagating it silently denies every exec on the host. The hook signature in libbpf is just (struct linux_binprm *).
type: feedback
originSessionId: 621387c2-943d-4e98-9fe3-2fe6a8adf4f4
---
When writing a BPF LSM hook for `bprm_check_security` (process-create
deny path) with libbpf, the **only** correct signature is:

```c
SEC("lsm/bprm_check_security")
int BPF_PROG(handle_bprm_check, struct linux_binprm *bprm)
{
    return 0;  // 0 = allow, -EPERM = deny
}
```

Adding an `int ret_in` argument and forwarding it ("if ret_in != 0
return ret_in;") looks reasonable — many examples online claim BPF LSM
hooks receive the previous module's return value as a trailing
argument, and forwarding it would let your hook compose nicely with
LSM stacking. **But for `bprm_check_security` specifically, the
trailing value isn't always 0**, so this pattern silently returns a
non-zero deny on every exec the moment your program loads — the
entire host effectively freezes (sshd can't fork-exec, cron stalls,
new processes die before they start). Only the agent's own logging
keeps producing entries because that's already-running code.

**Why:** burned ~30 minutes of M6.6 chasing this. The symptom
(`exec=0` in stats while `file_open` and `exit` keep counting) looks
like a verifier issue or a bad block-list lookup. It is neither.

**How to apply:**
- For LSM hooks declared via `BPF_PROG`, match the kernel's documented
  hook signature exactly. Don't add a final `int retval`. If you need
  the previous return for a particular hook (e.g. `inode_getattr`
  patterns), check the hook's actual `LSM_HOOK(...)` definition first.
- If you see a Linux host where `exec=0` in your stats while everything
  else looks fine, suspect this immediately — *before* you start
  bisecting your block-list logic.

The fix is one line: drop the extra parameter.
