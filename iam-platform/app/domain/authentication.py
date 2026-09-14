from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

try:
    import bcrypt
except ImportError:
    bcrypt = None

from ..core.validation import require_password

SESSION_LIFETIME = timedelta(hours=8)


def _argon2_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=int(os.environ.get("ARGON2_TIME_COST", "3")),
        memory_cost=int(os.environ.get("ARGON2_MEMORY_COST_KIB", "65536")),
        parallelism=int(os.environ.get("ARGON2_PARALLELISM", "2")),
    )


def hash_password(password: str) -> str:
    return _argon2_hasher().hash(require_password(password))


def verify_password(password: str, password_hash: str) -> bool:
    try:
        if password_hash.startswith("$argon2"):
            return _argon2_hasher().verify(password_hash, password)
        if password_hash.startswith("$2") and bcrypt is not None:
            # Legacy hashes remain verifiable so existing accounts can migrate on login.
            return bool(bcrypt.checkpw(password.encode(), password_hash.encode()))
        if password_hash.startswith("scrypt$"):
            _, salt_hex, digest_hex = password_hash.split("$", 2)
            candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1)
            return hmac.compare_digest(candidate.hex(), digest_hex)
    except (InvalidHashError, VerificationError, VerifyMismatchError, ValueError, TypeError):
        return False
    return False


def hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_session() -> tuple[str, datetime]:
    session_id = secrets.token_urlsafe(32)
    return session_id, now() + SESSION_LIFETIME


def new_reset_token(lifetime: timedelta) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    return token, now() + lifetime
