from pydantic import BaseModel, ConfigDict, Field


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(StrictRequest):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=255)


class UserCreateRequest(StrictRequest):
    username: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=3, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=255)


class UserUpdateRequest(StrictRequest):
    email: str | None = Field(default=None, min_length=3, max_length=255)
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    is_active: bool | None = None


class NamedResourceRequest(StrictRequest):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)


class ResourceUpdateRequest(StrictRequest):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)


class PermissionCreateRequest(StrictRequest):
    resource: str = Field(min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=255)


class ApplicationCreateRequest(StrictRequest):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)


class ApplicationUpdateRequest(StrictRequest):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
