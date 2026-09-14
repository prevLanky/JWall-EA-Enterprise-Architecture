from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


class SecretProtectionError(Exception):
    """Raised when an encrypted secret cannot be safely protected or recovered."""


class SecretProtector:
    """Replaceable authenticated-encryption boundary for reversible secrets."""

    def __init__(self, key: bytes):
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError) as error:
            raise SecretProtectionError("invalid TOTP encryption key") from error

    @classmethod
    def from_environment(cls) -> "SecretProtector":
        configured_key = os.environ.get("TOTP_ENCRYPTION_KEY")
        if not configured_key:
            raise SecretProtectionError("TOTP_ENCRYPTION_KEY is required for MFA operations")
        return cls(configured_key.encode("ascii"))

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken as error:
            raise SecretProtectionError("encrypted TOTP secret could not be verified") from error
