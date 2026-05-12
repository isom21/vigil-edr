"""POST /api/sigma/compile must not 500 on malformed YAML.

Review HIGH #7 / #5: pySigma re-raises plain `yaml.YAMLError` from
`from_yaml`, which the previous handler didn't catch, falling into
FastAPI's default 500 and leaving rule authors staring at
"internal server error". The service layer now converts every YAML
parse error to a SigmaCompileError carrying line/column, and the API
returns SigmaCompileResponse(ok=False, error=...) like every other
parse failure.
"""

from __future__ import annotations

import pytest

from app.services.sigma import SigmaCompileError, compile_yaml


def test_compile_yaml_surfaces_yaml_scanner_error_with_line_column() -> None:
    bad = "this is: not valid yaml\n  - bad indent: x\n -wrong"
    with pytest.raises(SigmaCompileError) as exc:
        compile_yaml(bad)
    msg = str(exc.value).lower()
    assert "yaml parse error" in msg
    assert "line" in msg
    assert "column" in msg


def test_compile_yaml_surfaces_tab_indentation_error() -> None:
    bad = "title: foo\n\tdetection:"
    with pytest.raises(SigmaCompileError) as exc:
        compile_yaml(bad)
    assert "yaml parse error" in str(exc.value).lower()


def test_compile_yaml_surfaces_truncated_flow_node() -> None:
    bad = "detection:\n  selection: {a:"
    with pytest.raises(SigmaCompileError) as exc:
        compile_yaml(bad)
    assert "yaml parse error" in str(exc.value).lower()


def test_compile_yaml_sigma_error_path_still_works() -> None:
    # Valid YAML, but missing logsource — should hit the SigmaError branch
    # (no log source). Same SigmaCompileError surface, different prefix.
    bad = "title: a\ndetection: {bad}"
    with pytest.raises(SigmaCompileError) as exc:
        compile_yaml(bad)
    assert (
        "sigma parse error" in str(exc.value).lower()
        or "yaml parse error" in str(exc.value).lower()
    )


@pytest.mark.asyncio
async def test_api_compile_returns_200_with_ok_false_on_malformed_yaml(
    http_client, admin_headers
) -> None:
    bad = "this is: not valid yaml\n  - bad indent: x\n -wrong"
    resp = await http_client.post("/api/sigma/compile", json={"body": bad}, headers=admin_headers)
    # The handler converts SigmaCompileError into a structured 200 response
    # so the editor can render the parser context inline; 500s would mean
    # we regressed to the pre-fix behaviour.
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert "yaml parse error" in body["error"].lower()
    assert "line" in body["error"].lower()


@pytest.mark.asyncio
async def test_api_compile_valid_rule_still_compiles(http_client, admin_headers) -> None:
    good = """
title: smoke
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        process.name: nc
    condition: selection
"""
    resp = await http_client.post("/api/sigma/compile", json={"body": good}, headers=admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["query"]
