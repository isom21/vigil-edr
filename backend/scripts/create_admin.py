"""Bootstrap the first admin user.

Usage:
    python -m scripts.create_admin --email admin@example.local --password 'change-me-later'
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.security import hash_password
from app.models import User, UserRole


async def main(email: str, password: str) -> int:
    email = email.lower()
    async with SessionLocal() as db:
        existing = (
            await db.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if existing:
            print(f"user {email} already exists (id={existing.id})", file=sys.stderr)
            return 1
        user = User(email=email, password_hash=hash_password(password), role=UserRole.ADMIN)
        db.add(user)
        await db.commit()
        print(f"created admin user id={user.id} email={email}")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.email, args.password)))
