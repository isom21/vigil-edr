# Curated Sigma rule pack

The Vigil manager ships with a default pack of Sigma rules covering
the highest-yield MITRE ATT&CK techniques across four tactics:

| Tactic | Subdirectory | Rules |
|--------|--------------|-------|
| Initial Access | `initial_access/` | T1078 / T1133 / T1189 / T1190 / T1566 |
| Execution | `execution/` | T1059.x / T1106 / T1218.005 |
| Persistence | `persistence/` | T1053.005 / T1098 / T1505.003 / T1543.x / T1547.x |
| Credential Access | `credential_access/` | T1003.x / T1110.003 / T1212 / T1555.003 / T1558.x |

## How the pack lands in the database

`app/services/rule_pack.py:load_rule_pack` runs at manager boot (see
`app/main.py` lifespan). It walks this directory, parses every
`*.yml` it finds, compiles the rule via `app/services/sigma.py:compile_yaml`
and either INSERTs the row (first run) or UPDATEs it (body changed
between commits, identified by `sha256` of the YAML body).

Key behaviours:

* **Stable Sigma UUIDs.** Each rule's `id:` field is a UUID v4 chosen
  once when the rule was authored, hard-coded in the YAML, and never
  regenerated. The Sigma id is also the primary key of the resulting
  `rules` row.
* **Operator overrides win.** When the loader updates an existing row
  it refreshes `name`, `description`, `body`, `sigma_compiled`,
  `mitre_techniques` and bumps `revision`. It leaves `enabled`,
  `action` and `severity` alone. Tune a rule down to `alert` in the
  UI and the next manager restart will not undo it.
* **One bad rule does not stop boot.** Parse errors, invalid UUIDs and
  Sigma compile failures get logged with a warning and counted into
  `RulePackReport.skipped`. The other files in the same directory
  still load.
* **Opt out.** Set `VIGIL_RULE_PACK_LOAD_ON_BOOT=0` to skip the
  loader entirely. Useful in tests that seed their own rule fixtures.
* **Audit trail.** Every insert / update writes a `rule.create` /
  `rule.update` row to `audit_log` under the system actor, so the
  chain stays continuous across restarts.

## Adding a new rule

1. Pick the right tactic subdirectory (`initial_access/`,
   `execution/`, `persistence/`, or `credential_access/`).
2. Pick a filename of the form `t<technique_id>_<short_description>.yml`
   (e.g. `t1059.001_powershell_encoded_command.yml`). Lowercase, dots
   in the technique ID, underscores elsewhere.
3. Generate a UUID v4 once and commit it as the rule's `id:` field —
   `python -c 'import uuid; print(uuid.uuid4())'`. Do NOT regenerate
   it on subsequent edits; that's the rule's stable identity.
4. Required Sigma front-matter:

   ```yaml
   title: <short title>
   id: <uuid v4>
   status: experimental | test | stable
   description: |
     <multi-line description>
   references:
     - <url>
   author: edr-curated
   date: <YYYY-MM-DD>
   tags:
     - attack.<tactic>            # one of: initial_access, execution,
                                  # persistence, credential_access, ...
     - attack.t<technique_id>     # e.g. attack.t1059.001
   logsource:
     product: windows | linux | macos
     category: process_creation | file_event | registry_set | ...
     service: <optional, e.g. security>
   detection:
     selection:
       <field>: <value>
     condition: selection
   level: informational | low | medium | high | critical
   ```

5. Optional but encouraged: a `falsepositives:` list and a `fields:`
   list to surface in the alert UI.
6. Compile-check locally: `python -c "from app.services.sigma import compile_yaml; compile_yaml(open('path/to/rule.yml').read())"`.
7. Submit a PR — the curated pack is reviewed by the EDR maintainers
   before merge.

## Why ECS field names?

Rules target ECS field names (`process.name`, `registry.path`,
`file.path`, etc.) because the manager indexes telemetry under those
names. The `Field mapping pipeline` work that lets you write rules
against Sysmon Event IDs and have them auto-translate to ECS is out
of scope for the Phase 1 curated pack; downstream Sigma open-source
rules can be overlaid once that lands.

## Where this pack stops

This is a deliberately small, high-precision starter set. Real
production deployments overlay:

* The [SigmaHQ open-source rule library][sigma].
* Threat-intel IOC feeds (see Phase 1 #1.9 — intel ingest).
* Tenant-specific anomaly detections (Phase 1 #1.11 process baselining).

Operators are expected to tune the curated rules to their environment
and add their own. The loader's "operator overrides win" policy is
specifically what makes that workflow safe — re-running the loader on
every manager restart never reverts the operator's work.

[sigma]: https://github.com/SigmaHQ/sigma
