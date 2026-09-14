from __future__ import annotations

from dataclasses import dataclass

import pyotp

from .secrets import SecretProtector


@dataclass(frozen=True)
class TotpEnrollment:
    provisioning_uri: str


class TotpService:
    """RFC 6238 TOTP operations with secrets delegated to SecretProtector."""

    def __init__(self, protector: SecretProtector, issuer: str = "IAM Platform"):
        self.protector = protector
        self.issuer = issuer

    def enroll(self, username: str) -> tuple[bytes, TotpEnrollment]:
        secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=self.issuer)  # pyright: ignore[reportUnknownMemberType]
        return self.protector.encrypt(secret.encode("ascii")), TotpEnrollment(uri)

    def verify(self, encrypted_secret: bytes, code: str) -> bool:
        if not code.isdigit() or len(code) != 6:
            return False
        secret = self.protector.decrypt(encrypted_secret).decode("ascii")
        return pyotp.TOTP(secret).verify(code, valid_window=1)
