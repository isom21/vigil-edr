---
name: Plan first on ambitious work
description: For large or risky projects, ask design questions and produce a written plan before writing any code, even when auto mode is active.
type: feedback
originSessionId: 04069394-44f9-41e9-9017-3a82415636ec
---
Before starting any non-trivial / multi-component build, ask focused design questions and produce a written milestone plan. Do not jump straight into code, even when auto mode is active.

**Why:** When kicking off the EDR project, the user explicitly said "ask me design questions and plan your actions before you start. take your time and make no mistakes." Acting before clarifying would have committed to wrong tech choices that are expensive to reverse (e.g., language for the agent, kernel-mode scope, transport protocol).

**How to apply:**
- Use AskUserQuestion in batches of up to 4 well-scoped questions, prioritizing the most architecture-shaping decisions first.
- Briefly state your mental model and recommended scope before asking, so the user can correct framing rather than just answer questions in isolation.
- After answers, write a structured plan (architecture, data model, milestones, risks) before any file changes.
- Auto mode does *not* override an explicit "plan first" instruction. Auto mode's "execute immediately" applies to routine work, not greenfield architecture.
- Don't ask trivia questions (color of the bikeshed, naming) up front — defer those into the work itself.
