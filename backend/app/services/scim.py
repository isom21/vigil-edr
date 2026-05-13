"""SCIM 2.0 helpers — translate between SCIM wire shapes and User rows.

Reference: RFC 7643 (schema) + RFC 7644 (protocol).

We support the User core schema only. Groups are out of scope for v1
(commented in tests). The Enterprise User extension is read on inbound
PATCH/PUT — `enterprise.organization` is ignored, but `enterprise.role`
is mapped to our local role enum.

Local field mapping:

    SCIM userName      -> users.email      (canonical)
    SCIM emails[primary].value -> users.email (fallback if no userName)
    SCIM externalId    -> users.scim_external_id
    SCIM displayName   -> ignored (not stored, but echoed back)
    SCIM active=false  -> users.disabled=true (PATCH only — POST creates
                          a disabled row too if active=false, mirroring
                          Okta's behaviour for staged users)
    SCIM Enterprise extension role -> users.role (clamped to enum)

The `oidc_issuer` column doubles as the SCIM tenant key — when the IdP
provisions a user, we stamp `oidc_issuer` with the configured OIDC
issuer URL (when set) or with a sentinel "scim:vigil" string for
deployments that haven't enabled OIDC. This lets the partial unique
index `(oidc_issuer, scim_external_id)` keep externalIds disjoint
between IdPs even when neither tenant has OIDC enabled.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from app.core.config import settings
from app.models import User, UserRole

# The schema URN strings the IdPs send. We don't validate these
# strictly — vendor extensions add their own urns and rejecting an
# unknown urn breaks Okta's "extended schema" flow.
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

# Sentinel issuer when OIDC isn't configured. Stable across restarts so
# the unique index works across processes.
DEFAULT_SCIM_ISSUER = "scim:vigil"


def scim_issuer() -> str:
    """Return the issuer URL to stamp on SCIM-provisioned users.

    Uses the configured OIDC issuer when set so SCIM-provisioned users
    can later log in via SSO without a second row appearing. Falls back
    to a sentinel for OIDC-disabled deployments.
    """
    return settings.oidc_issuer_url or DEFAULT_SCIM_ISSUER


# ----------------------------------------------------------------------
# Token helpers.
# ----------------------------------------------------------------------


def generate_scim_token() -> str:
    """Return a fresh URL-safe random bearer token.

    No `edr_` prefix — IdPs paste this directly into their config and
    operators expect it to look like a generic bearer secret.
    """
    return secrets.token_urlsafe(48)


def hash_scim_token(raw: str) -> str:
    """sha256-hex of the raw token. Matches `hash_api_token_secret` so
    the constant-time comparison helper still applies."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# Read side: User -> SCIM JSON.
# ----------------------------------------------------------------------


def to_scim_user(user: User, *, location_base: str = "") -> dict[str, Any]:
    """Render a User row as a SCIM User Resource."""
    schemas = [SCIM_USER_SCHEMA]
    body: dict[str, Any] = {
        "schemas": schemas,
        "id": str(user.id),
        "userName": user.email,
        "active": not user.disabled,
        "emails": [
            {
                "value": user.email,
                "primary": True,
                "type": "work",
            }
        ],
        "meta": {
            "resourceType": "User",
            "created": user.created_at.isoformat() if user.created_at else None,
            "lastModified": user.updated_at.isoformat() if user.updated_at else None,
            "location": f"{location_base}/Users/{user.id}" if location_base else None,
        },
    }
    if user.scim_external_id:
        body["externalId"] = user.scim_external_id
    # Enterprise extension carries the role so the IdP can render it.
    schemas.append(SCIM_ENTERPRISE_SCHEMA)
    body[SCIM_ENTERPRISE_SCHEMA] = {"role": user.role.value if user.role else None}
    return body


# ----------------------------------------------------------------------
# Write side: SCIM -> internal fields.
# ----------------------------------------------------------------------


def _coerce_role(raw: str | None) -> UserRole:
    """Map a SCIM role string to our local role enum. Unknown / missing
    falls back to viewer, the least-privileged role."""
    if not raw:
        return UserRole.VIEWER
    candidate = raw.strip().lower()
    for role in UserRole:
        if role.value == candidate:
            return role
    return UserRole.VIEWER


def _extract_primary_email(payload: dict[str, Any]) -> str | None:
    emails = payload.get("emails")
    if not isinstance(emails, list):
        return None
    # Prefer the entry tagged primary=true; otherwise the first one.
    primary = next(
        (e.get("value") for e in emails if isinstance(e, dict) and e.get("primary")),
        None,
    )
    if primary:
        return str(primary).lower()
    first = next(
        (e.get("value") for e in emails if isinstance(e, dict) and e.get("value")),
        None,
    )
    return str(first).lower() if first else None


def parse_scim_user_create(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate an inbound SCIM Create / PUT body to the local-field
    shape `apply_scim_user_fields` consumes.

    Always returns a dict with keys: ``email``, ``external_id``,
    ``role``, ``disabled``. Missing email raises ValueError — the caller
    turns that into a 400.
    """
    user_name = payload.get("userName")
    email = (
        str(user_name).lower()
        if isinstance(user_name, str) and user_name
        else _extract_primary_email(payload)
    )
    if not email or "@" not in email:
        raise ValueError("userName / emails must contain a valid email address")

    enterprise = payload.get(SCIM_ENTERPRISE_SCHEMA)
    role_raw: str | None = None
    if isinstance(enterprise, dict):
        role_raw = enterprise.get("role")
    if not role_raw:
        role_raw = payload.get("role")

    active = payload.get("active", True)
    if not isinstance(active, bool):
        active = True

    return {
        "email": email,
        "external_id": payload.get("externalId"),
        "role": _coerce_role(role_raw),
        "disabled": not active,
    }


def apply_scim_user_fields(user: User, fields: dict[str, Any]) -> None:
    """Apply a parsed-create dict to an existing User row."""
    if "email" in fields and fields["email"]:
        user.email = fields["email"]
    if "external_id" in fields and fields["external_id"] is not None:
        user.scim_external_id = str(fields["external_id"])
    if "role" in fields and fields["role"] is not None:
        user.role = fields["role"]
    if "disabled" in fields and fields["disabled"] is not None:
        user.disabled = bool(fields["disabled"])


# ----------------------------------------------------------------------
# PATCH support.
# ----------------------------------------------------------------------


def _apply_patch_value(user: User, path: str | None, value: Any) -> None:
    """Apply a single (path, value) write to the user row.

    `path=None` means the value is a full object replacement — that's
    how Azure AD encodes "set these attributes" — so we walk its keys.
    """
    if path is None:
        if isinstance(value, dict):
            for k, v in value.items():
                _apply_patch_value(user, k, v)
        return
    norm = path.strip().lower()
    # Bracketed filter expressions like `emails[type eq "work"].value` —
    # not supported; the typical deprovisioning ops don't use them.
    # Stripping anything inside brackets keeps `emails[primary eq true]`
    # from raising while we ignore the filter.
    if "[" in norm:
        norm = norm.split("[", 1)[0]
    if norm == "active":
        if isinstance(value, str):
            user.disabled = value.strip().lower() not in ("true", "1", "yes")
        else:
            user.disabled = not bool(value)
        return
    if norm == "username":
        if isinstance(value, str) and value:
            user.email = value.lower()
        return
    if norm == "externalid":
        user.scim_external_id = str(value) if value is not None else None
        return
    if norm == "emails":
        # The whole emails array got replaced. Extract the primary.
        new_email = _extract_primary_email({"emails": value if isinstance(value, list) else []})
        if new_email:
            user.email = new_email
        return
    if norm.startswith(SCIM_ENTERPRISE_SCHEMA.lower()):
        # The enterprise-extension role.
        if isinstance(value, dict) and "role" in value:
            user.role = _coerce_role(value.get("role"))
        return
    # Unknown attribute — silently ignore. Per RFC 7644 §3.5.2 the
    # server may either ignore or 400; ignoring is friendlier with
    # vendors that send vendor-specific extensions.


def apply_scim_patch(user: User, ops: list[dict[str, Any]]) -> None:
    """Apply a list of PATCH operations in order. Each op is the
    {op, path, value} dict the body schema exposes."""
    for raw in ops:
        op = str(raw.get("op", "")).strip().lower()
        path = raw.get("path")
        value = raw.get("value")
        if op in ("add", "replace"):
            _apply_patch_value(user, path, value)
        elif op == "remove":
            # Remove only makes sense for nullable single-valued attrs
            # like externalId. For `active`, treat remove as "set
            # active=false" because that's what Okta sends for
            # deprovisioning.
            norm = (path or "").strip().lower()
            if norm == "active":
                user.disabled = True
            elif norm == "externalid":
                user.scim_external_id = None
            # Other removes — ignore (we don't store the field).
        # Unknown op — ignore.
