"""M-rbac-viewer #9: viewer role reads alerts/hosts/rules, not just admin/analyst.

Reviewer's MEDIUM #9: every read endpoint was gated on RequireAnalyst,
so a viewer login returned 403 on every page even though
`docs/rbac.md` documented the role as "read-only on alerts, hosts,
rules". The fix: add `RequireViewer` (admin+analyst+viewer) on the
read endpoints, keep `RequireAnalyst` on write endpoints.

These tests pin the role gates by introspection — the alternative is
booting the full app + a viewer JWT + httpx, which flakes under
shared test-engine state in this suite (see the comment at the bottom
of test_rate_limit_role_classification.py).
"""

from __future__ import annotations

import inspect

import pytest


def _read_endpoint_actor_deps(module) -> dict[str, str]:
    """Walk a router module's source and return {function_name: dep}
    for every endpoint whose `@router.get(...)` decorator we can see.
    The dep is whichever of Require{Admin,Analyst,Viewer} appears in
    its parameter list."""
    src = inspect.getsource(module)
    lines = src.splitlines()
    out: dict[str, str] = {}
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("@router.get(") or line.startswith("@router.delete("):
            method = "get" if "get(" in line else "delete"
            # Find the async def on a subsequent line.
            j = i + 1
            while j < len(lines) and not lines[j].lstrip().startswith("async def "):
                j += 1
            if j >= len(lines):
                i += 1
                continue
            func_name = lines[j].lstrip().split("def ", 1)[1].split("(", 1)[0]
            # Find the dep within the next ~30 lines (signature body).
            dep = ""
            for k in range(j, min(j + 30, len(lines))):
                for cand in ("RequireAdmin", "RequireAnalyst", "RequireViewer"):
                    if cand in lines[k]:
                        dep = cand
                        break
                if dep:
                    break
            if dep:
                out[f"{method}:{func_name}"] = dep
        i += 1
    return out


def test_alerts_read_endpoints_admit_viewer() -> None:
    """Every GET on alerts.py that gates on a Require* must allow
    viewer. The exception is the SSE stream which uses
    CurrentActorStream (any-authenticated; the per-event filter
    handles scope)."""
    import app.api.alerts as alerts

    deps = _read_endpoint_actor_deps(alerts)
    # Endpoints that should now admit viewer:
    expected = {
        "get:list_alerts",
        "get:alert_stats",
        "get:get_alert",
        "get:get_alert_context",
        "get:get_process_detail",
    }
    for key in expected:
        assert deps.get(key) == "RequireViewer", (
            f"alerts {key}: expected RequireViewer, got {deps.get(key)!r}"
        )


def test_alerts_write_endpoints_still_require_analyst() -> None:
    """Writes stay above viewer — viewers can read but can't move
    alert state or assign."""
    import inspect

    import app.api.alerts as alerts

    src = inspect.getsource(alerts)
    # change_state + assign are the two write endpoints. Both should
    # carry `actor: RequireAnalyst`.
    assert "async def change_state" in src
    assert "async def assign" in src
    # Crude but reliable: both should be RequireAnalyst, not the
    # broader Viewer dep.
    for fn in ("change_state", "assign"):
        # Find the function and pull its signature lines.
        start = src.find(f"async def {fn}")
        sig_block = src[start : start + 400]
        assert "RequireAnalyst" in sig_block, f"{fn} should keep RequireAnalyst"
        assert "RequireViewer" not in sig_block, f"{fn} should not relax to RequireViewer"


def test_hosts_read_endpoints_admit_viewer() -> None:
    import app.api.hosts as hosts

    deps = _read_endpoint_actor_deps(hosts)
    expected = {
        "get:list_hosts",
        "get:host_stats",
        "get:get_host",
        "get:host_live_telemetry",
    }
    for key in expected:
        assert deps.get(key) == "RequireViewer", f"hosts {key}: got {deps.get(key)!r}"
    # Writes stay admin.
    assert deps.get("get:update_host", "") in ("", "RequireAdmin")  # update is PATCH not GET
    assert deps.get("delete:delete_host") == "RequireAdmin"


def test_rules_read_endpoints_admit_viewer() -> None:
    import app.api.rules as rules

    deps = _read_endpoint_actor_deps(rules)
    expected = {"get:list_rules", "get:rule_stats", "get:get_rule"}
    for key in expected:
        assert deps.get(key) == "RequireViewer", f"rules {key}: got {deps.get(key)!r}"
    assert deps.get("delete:delete_rule") == "RequireAdmin"


@pytest.mark.asyncio
async def test_require_viewer_admits_all_three_roles() -> None:
    """The dep itself accepts admin, analyst, and viewer — not just
    a subset."""
    from app.core.deps import Actor, require_role
    from app.models import User, UserRole

    dep = require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
    for role in (UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER):
        actor = Actor(user=User(role=role), kind="user")
        result = await dep(actor)
        assert result is actor, f"RequireViewer should admit {role.name}"
