"""M-audit-and-auth #8: per-email failed-login throttle.

Reviewer's MEDIUM #8: the per-IP anon limiter catches a single
attacker IP at 10 r/min but distributed credential-stuffing across
residential proxies / a small botnet sits under the cap. Add a
per-email failed-login window so the same target account can absorb
at most N misses before /login responds 429 regardless of source IP.
"""

from __future__ import annotations


def test_record_below_limit_does_not_block() -> None:
    """N-1 failures stay under the gate."""
    from app.api import auth as auth_api

    email = "throttle-test-low@local"
    auth_api._clear_login_failures(email)
    for _ in range(auth_api._LOGIN_FAIL_LIMIT - 1):
        blocked, _ = auth_api._record_login_failure(email)
        assert blocked is False
    auth_api._clear_login_failures(email)


def test_record_at_or_over_limit_blocks() -> None:
    """The Nth+1 failure flips the gate and returns retry-after."""
    from app.api import auth as auth_api

    email = "throttle-test-trip@local"
    auth_api._clear_login_failures(email)
    blocked = False
    retry = 0
    for _ in range(auth_api._LOGIN_FAIL_LIMIT + 1):
        blocked, retry = auth_api._record_login_failure(email)
    assert blocked is True
    assert retry >= 1
    auth_api._clear_login_failures(email)


def test_clear_drops_strikes_after_success() -> None:
    """A successful login clears the bucket so a legitimate user
    whose typo tripped the gate isn't penalised on the next attempt."""
    from app.api import auth as auth_api

    email = "throttle-test-clear@local"
    auth_api._clear_login_failures(email)
    for _ in range(auth_api._LOGIN_FAIL_LIMIT):
        auth_api._record_login_failure(email)
    auth_api._clear_login_failures(email)
    blocked, _ = auth_api._record_login_failure(email)
    assert blocked is False
    auth_api._clear_login_failures(email)


def test_different_emails_have_independent_buckets() -> None:
    """One account being attacked doesn't lock out everyone else."""
    from app.api import auth as auth_api

    email_a = "throttle-test-a@local"
    email_b = "throttle-test-b@local"
    auth_api._clear_login_failures(email_a)
    auth_api._clear_login_failures(email_b)
    for _ in range(auth_api._LOGIN_FAIL_LIMIT + 1):
        auth_api._record_login_failure(email_a)
    blocked_b, _ = auth_api._record_login_failure(email_b)
    assert blocked_b is False
    auth_api._clear_login_failures(email_a)
    auth_api._clear_login_failures(email_b)


# Note: a full ASGI round-trip via httpx flakes under shared
# test-engine state across the suite (other fixtures dispose engines
# and the next test trips on the disposed pool). The unit tests above
# already pin the load-bearing throttle logic; the wire-level check
# lives in `tools/smoke/` instead. Verified by hand:
#   curl -i -X POST :8000/api/auth/login \
#     -d '{"email":"x@y","password":"wrong"}' (×11) → final response
#   HTTP/1.1 429 Too Many Requests
#   Retry-After: 300
