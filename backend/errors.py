"""Application errors. Each carries a friendly, user-safe message."""
from __future__ import annotations


class ScamLensError(Exception):
    status_code = 500
    code = "internal_error"
    user_message = "Something went wrong on our side. Please try again."

    def __init__(self, user_message: str | None = None, *, code: str | None = None, detail: str | None = None):
        if user_message:
            self.user_message = user_message
        if code:
            self.code = code
        super().__init__(detail or self.user_message)


class InvalidInputError(ScamLensError):
    status_code = 422
    code = "invalid_input"
    user_message = "Please provide a message to analyze."


class InputTooLargeError(ScamLensError):
    status_code = 413
    code = "input_too_large"
    user_message = "That input is too large."


class UnsupportedFileError(ScamLensError):
    status_code = 415
    code = "unsupported_file"
    user_message = "That file type is not supported."


class InvalidImageError(ScamLensError):
    status_code = 422
    code = "invalid_image"
    user_message = "That file is not a valid image. Upload a PNG, JPG or WebP screenshot."


class NoTextFoundError(ScamLensError):
    status_code = 422
    code = "no_text_found"
    user_message = "We couldn't extract readable text from this image. Try uploading a clearer screenshot."


class OCRUnavailableError(ScamLensError):
    status_code = 503
    code = "ocr_unavailable"
    user_message = "Screenshot reading is temporarily unavailable. Paste the message text instead."


class AIUnavailableError(ScamLensError):
    status_code = 503
    code = "ai_unavailable"
    user_message = "The AI analysis service is temporarily unavailable. Please try again."


class MalformedAIResponseError(ScamLensError):
    status_code = 502
    code = "ai_malformed_response"
    user_message = "The AI service returned an unexpected response. Please try again."


class RateLimitedError(ScamLensError):
    status_code = 429
    code = "rate_limited"
    user_message = "Too many requests. Please wait a moment and try again."


class AuthError(ScamLensError):
    status_code = 401
    code = "unauthorized"
    user_message = "This request is not authorized."


class NotFoundError(ScamLensError):
    status_code = 404
    code = "not_found"
    user_message = "We couldn't find that analysis."
