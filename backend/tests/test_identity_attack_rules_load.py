"""Identity-attack Sigma rule pack load coverage (Phase 2 #2.5).

Asserts that the 12 YAML files added under
`backend/sigma_rules/{credential_access,initial_access,persistence}/`
for Phase 2 #2.5 are:

  1. valid YAML with the required top-level keys (`id`, `title`,
     `level`, `detection`, `tags`);
  2. each tagged with at least one MITRE technique
     (`attack.t<id>...`), so the rule-pack loader can populate
     `Rule.mitre_techniques`;
  3. assigned a unique UUID across the whole new pack (no copy-
     paste collisions, no collision against the rest of the bundled
     rule library);
  4. picked up by `load_rule_pack()` when it walks the on-disk
     sigma_rules tree — every UUID lands as a Rule row.

These four invariants together are what an operator depends on for
"the new rules show up after I `git pull && systemctl restart vigil-
manager`". Anything looser and a typo'd UUID or missing technique
tag would silently slip through review.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
import yaml
from sqlalchemy import select

from app.models import Rule
from app.services.rule_pack import (
    _extract_mitre_techniques,
    load_rule_pack,
)

# UUIDs assigned to the 12 new rules. Pinned here (rather than read
# from disk) so a rename of a YAML file can't silently drop a rule
# from the pack without the test noticing.
_PACK_UUIDS: dict[str, str] = {
    "credential_access/t1558.001_golden_ticket_anomalous_lifetime.yml": (
        "6e3470e5-3b45-4c2f-bfc6-9767e8b5d384"
    ),
    "credential_access/t1003.006_dcsync_replication_request.yml": (
        "5cc74fef-0f45-4cfe-a246-217c93713cdd"
    ),
    "credential_access/t1207_dcshadow_rogue_dc_registration.yml": (
        "4f59f604-af80-4ce0-a916-49db9e98294d"
    ),
    "credential_access/t1550.002_pass_the_hash_ntlm_reuse.yml": (
        "d582e81f-dc77-45a1-a4bf-3425cf279c09"
    ),
    "credential_access/t1550.003_pass_the_ticket_reuse.yml": (
        "cc7b494f-d913-4eb1-ba7c-3e79fb46238e"
    ),
    "credential_access/t1003.005_cached_credential_dump_security_hive.yml": (
        "2c2a8b2f-b198-4298-b49b-3d6e8b3887a3"
    ),
    "credential_access/t1003.002_sam_hive_access.yml": ("0b3d9b7c-5ad8-4277-8c88-d96d44f86452"),
    "credential_access/t1187_forced_authentication_responder.yml": (
        "496290cc-4e6b-4f22-8612-69c59eedcb9d"
    ),
    "initial_access/t1110.001_brute_force_password_guess_4625.yml": (
        "1e9744f2-d2e6-4a4c-ac4e-073e368bfff7"
    ),
    "initial_access/t1110.001_rdp_brute_force.yml": ("040deb37-7e99-49f3-8e86-034a0a604edf"),
    "persistence/t1136.001_new_local_admin_account.yml": ("96546c52-d1f7-4732-85fa-fc032d347981"),
    "persistence/t1136.002_new_domain_admin_account.yml": ("d3ba3c36-042b-4b99-a55b-e152707b1c9a"),
}


def _pack_root() -> Path:
    """Locate `backend/sigma_rules/` relative to this test file."""
    return Path(__file__).resolve().parents[1] / "sigma_rules"


def _read_pack_rule(rel_path: str) -> dict:
    """Read + safe-load one of the new YAML files."""
    path = _pack_root() / rel_path
    body = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(body)
    assert isinstance(doc, dict), f"{rel_path}: top-level YAML must be a mapping"
    return doc


@pytest.mark.parametrize("rel_path,expected_uuid", sorted(_PACK_UUIDS.items()))
def test_rule_is_valid_yaml_with_required_keys(rel_path: str, expected_uuid: str) -> None:
    """Each rule parses as YAML, has the keys the loader needs, and
    pins the UUID this test expects."""
    doc = _read_pack_rule(rel_path)
    for key in ("title", "id", "description", "tags", "logsource", "detection", "level"):
        assert key in doc, f"{rel_path}: missing required top-level key `{key}`"
    # UUID parses and matches the manifest above.
    parsed = UUID(str(doc["id"]))
    assert str(parsed) == expected_uuid, (
        f"{rel_path}: id changed since pack manifest was pinned "
        f"(got {parsed}, expected {expected_uuid})"
    )
    # Level normalises to one the loader understands.
    level = str(doc["level"]).strip().lower()
    assert level in {"informational", "info", "low", "medium", "high", "critical"}, (
        f"{rel_path}: level `{doc['level']}` is not one of the recognised severities"
    )


@pytest.mark.parametrize("rel_path", sorted(_PACK_UUIDS))
def test_rule_has_at_least_one_mitre_technique_tag(rel_path: str) -> None:
    """Each rule's `tags:` block contains at least one
    `attack.t<digit>...` tag so the rule-pack loader populates
    `Rule.mitre_techniques`. A rule that lands without a technique tag
    is invisible to MITRE coverage tooling, so this property is what
    makes "covers technique X" a real claim instead of a description-
    field promise."""
    doc = _read_pack_rule(rel_path)
    tags = doc.get("tags") or []
    assert isinstance(tags, list), f"{rel_path}: tags must be a list"
    techniques = _extract_mitre_techniques([str(t) for t in tags])
    assert techniques, f"{rel_path}: no `attack.t<id>` technique tag found in {tags!r}"


def test_pack_uuids_are_globally_unique() -> None:
    """The 12 new UUIDs must be distinct from each other AND from
    every UUID already present in `backend/sigma_rules/`. Catches
    the failure mode where someone copy-pastes a rule, edits the
    body, but forgets to roll the `id:` field."""
    # Within-pack uniqueness.
    assert len(set(_PACK_UUIDS.values())) == len(_PACK_UUIDS), (
        "duplicate UUID in the new pack manifest"
    )

    # Cross-pack uniqueness against everything else in sigma_rules/.
    pack_set = {UUID(v) for v in _PACK_UUIDS.values()}
    new_paths = {(_pack_root() / rel).resolve() for rel in _PACK_UUIDS}
    other_uuids: dict[UUID, Path] = {}
    for path in sorted(_pack_root().rglob("*.yml")):
        if path.resolve() in new_paths:
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or "id" not in doc:
            continue
        try:
            other_uuids[UUID(str(doc["id"]))] = path
        except (ValueError, TypeError):
            continue
    collisions = pack_set & set(other_uuids)
    assert not collisions, (
        f"UUID collision with existing rule pack files: "
        f"{[(str(u), str(other_uuids[u])) for u in collisions]}"
    )


@pytest.mark.asyncio
async def test_rule_pack_loader_picks_up_all_12_new_rules(db_session) -> None:
    """End-to-end: run the real loader against `backend/sigma_rules/`
    and confirm every one of the 12 new UUIDs lands as a Rule row
    with `mitre_techniques` populated. This is the property an
    operator relies on after a `git pull && restart`."""
    await load_rule_pack(db_session, root=_pack_root())

    expected_ids = [UUID(v) for v in _PACK_UUIDS.values()]
    rows = (await db_session.execute(select(Rule).where(Rule.id.in_(expected_ids)))).scalars().all()
    by_id = {r.id: r for r in rows}
    missing = [str(uid) for uid in expected_ids if uid not in by_id]
    assert not missing, f"loader did not pick up these UUIDs: {missing}"

    # Every new row got techniques populated (assuming the column
    # exists on the Rule model — it has been since Phase 1 #1.14).
    if hasattr(Rule, "mitre_techniques"):
        for uid in expected_ids:
            techniques = by_id[uid].mitre_techniques or []
            assert techniques, (
                f"rule {uid} loaded with no mitre_techniques — check its `attack.t<id>` tag"
            )
