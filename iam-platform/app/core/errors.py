from .status import HttpStatus


class IamError(Exception):
    """Single framework-neutral failure type; categories use factory functions."""

    def __init__(self, message: str, status: HttpStatus):
        super().__init__(message)
        self.message = message
        self.status = status

    def __str__(self) -> str:
        return self.message


def invalid_input(message: str) -> IamError:
    return IamError(message, HttpStatus.BAD_REQUEST)


def not_found(message: str) -> IamError:
    return IamError(message, HttpStatus.NOT_FOUND)


def conflict(message: str) -> IamError:
    return IamError(message, HttpStatus.CONFLICT)


def unauthorized(message: str = "authentication required") -> IamError:
    return IamError(message, HttpStatus.UNAUTHORIZED)


def forbidden(message: str = "operation is not authorized") -> IamError:
    return IamError(message, HttpStatus.FORBIDDEN)


def too_many_requests(message: str = "too many authentication attempts") -> IamError:
    return IamError(message, HttpStatus.TOO_MANY_REQUESTS)
