# backend/app/core/exceptions.py
"""
Custom HTTP Exceptions

All API errors use these structured exceptions.
The main app registers a handler that converts these to JSON responses
with consistent structure: {"error": {"code": "...", "message": "...", "details": {...}}}
"""

from fastapi import status


class OgunAIException(Exception):
    def __init__(self, status_code: int, error_code: str, message: str, details: dict = None):
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.details = details or {}
        super().__init__(message)


class AuthenticationError(OgunAIException):
    def __init__(self, message: str = "Authentication required"):
        super().__init__(status.HTTP_401_UNAUTHORIZED, "AUTHENTICATION_ERROR", message)


class AuthorizationError(OgunAIException):
    def __init__(self, message: str = "Permission denied"):
        super().__init__(status.HTTP_403_FORBIDDEN, "AUTHORIZATION_ERROR", message)


class NotFoundError(OgunAIException):
    def __init__(self, resource: str = "Resource", details: dict = None):
        super().__init__(status.HTTP_404_NOT_FOUND, "NOT_FOUND",
                         f"{resource} not found", details)


class ConflictError(OgunAIException):
    def __init__(self, message: str = "Conflict", details: dict = None):
        super().__init__(status.HTTP_409_CONFLICT, "CONFLICT", message, details)


class ValidationError(OgunAIException):
    def __init__(self, message: str = "Validation failed", details: dict = None):
        super().__init__(status.HTTP_422_UNPROCESSABLE_ENTITY,
                         "VALIDATION_ERROR", message, details)