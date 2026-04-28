class TokenBrokerError(Exception):
    """Base class for all broker errors."""


class ConfigurationError(TokenBrokerError):
    """Raised when required env vars are missing."""


class TokenFetchError(TokenBrokerError):
    """Raised when the upstream OAuth call fails."""


class RateLimitedError(TokenFetchError):
    """Raised specifically when upstream returns 429."""
