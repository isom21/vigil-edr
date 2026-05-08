---
name: EDR repo has commit.gpgsign disabled locally
description: In /mnt/d/priv/code/edr the local git config sets commit.gpgsign=false on user instruction; commit normally without -c overrides.
type: feedback
originSessionId: 04069394-44f9-41e9-9017-3a82415636ec
---
In `/mnt/d/priv/code/edr/` the local git config has `commit.gpgsign=false`. Commit normally — do not pass `-c commit.gpgsign=false` overrides, do not try to re-enable signing.

**Why:** User's global gitconfig has `commit.gpgsign=true` and signing key `E658564F28C31DB71CF425464D4DB6B42004B100`. GPG blocks on a passphrase prompt with no tty, which hung every commit attempt. User explicitly authorized disabling gpgsign at repo level for this private project ("disable gpgsign for the working directory entirely and you do the commits").

**How to apply:**
- For the EDR repo only, commit normally — local override is already in place.
- Do not assume the same in other repos under the user's account; the global default still signs commits in `/mnt/d/cycon/Work/**` (their work tree) and elsewhere.
- If a future commit fails because of signing, check `git config --local commit.gpgsign` first before assuming a deeper issue.
- The user's global identity (`tom.looser <tom.looser@cybercon.ch>`) is what `git commit` will use here unless told otherwise.
