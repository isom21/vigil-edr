---
name: TOTP over hardware-key 2FA on personal projects
description: Don't recommend YubiKey/WebAuthn for personal-project security designs; TOTP is the user's preference
type: feedback
originSessionId: 41838ce8-bbd2-4e23-85c0-b5b3a55ea93d
---
When designing security/access controls for the user's personal projects (EDR,
cloudlab, etc.), default to TOTP-based 2FA (Aegis, 1Password, Authy) rather
than hardware-key (YubiKey/WebAuthn).

**Why:** User has explicitly said they don't use a YubiKey for their local
git workflow either, so this is a settled preference, not a per-project
choice. The phishing-resistance gain of WebAuthn over TOTP is marginal for
solo personal projects.

**How to apply:** In architecture and access-control proposals, recommend
TOTP 2FA + a password manager. Note hardware keys only if the user later
introduces a team or enterprise context (Path D scenarios). Don't push
back on this preference.
