"""Auth payloads."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    # Plain str — email format is enforced at user-creation time; login just needs a match.
    email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    # Optional after M-frontend-auth #10 — the frontend now reads the
    # refresh token from the HttpOnly `vigil_refresh` cookie, but
    # existing scripted callers can still POST the body shape. One of
    # the two must be present.
    refresh_token: str | None = None


class LoginResponse(BaseModel):
    """Union return for POST /login. Either the TokenPair fields are
    set (no 2FA configured) or `mfa_required=True` with an
    `mfa_token` the client exchanges at /login/2fa. Splitting this in
    one shape keeps the wire compatible with scripted callers that
    only look at `access_token`."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str | None = None


class Login2FARequest(BaseModel):
    mfa_token: str = Field(min_length=1)
    # 6-digit TOTP code OR a recovery code. The server tries TOTP
    # first and falls back to recovery on miss.
    code: str = Field(min_length=1, max_length=32)


class TotpStatus(BaseModel):
    enabled: bool
    pending: bool


class TotpSetupResponse(BaseModel):
    # The base32-encoded shared secret + the otpauth:// URI for QR
    # rendering. Stored server-side as `totp_pending_secret_encrypted`
    # until the caller confirms it via /verify-setup.
    secret_base32: str
    provisioning_uri: str


class TotpVerifySetupRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8, pattern=r"^\d+$")


class TotpVerifySetupResponse(BaseModel):
    enabled: bool = True
    # One-shot view; the server stores only the bcrypt hashes.
    recovery_codes: list[str]


class TotpDisableRequest(BaseModel):
    # A current TOTP code or a recovery code. Required so a stolen
    # session can't silently disable 2FA on the account.
    code: str = Field(min_length=1, max_length=32)


class OidcDiscoveryResponse(BaseModel):
    """Tiny gate the SPA pings on /login to decide whether to render
    the 'Sign in with SSO' button. We deliberately surface only the
    boolean — the issuer URL / client id are operator-private."""

    enabled: bool
