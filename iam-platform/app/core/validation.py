from .errors import invalid_input

PASSWORD_MIN_LENGTH = 12


def require_text(value: object, field: str) -> str:
    """Return trimmed text or a shared application validation error."""

    if not isinstance(value, str) or not value.strip():
        raise invalid_input(f"{field} must be a non-empty string")
    normalized_value = value.strip()
    if len(normalized_value) > 255:
        raise invalid_input(f"{field} must be at most 255 characters")
    return normalized_value


def require_password(value: object, field: str = "password") -> str:
    password = require_text(value, field)
    if len(password) < PASSWORD_MIN_LENGTH:
        raise invalid_input(f"{field} must be at least {PASSWORD_MIN_LENGTH} characters")
    return password
