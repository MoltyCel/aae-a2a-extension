"""Identifiers fixed by the AAE A2A extension profile v1."""

# The extension URI is the identifier of this profile (spec section 2). It is an
# identifier first; HTTP access to it is not required for interoperability.
EXTENSION_URI = "https://moltrust.ch/extensions/aae/v1"

# The only AAE revision this profile version is built against.
AAE_DRAFT = "draft-kroehl-agentic-trust-aae-02"

# A2A service parameter used for extension activation (A2A v1.0 section 3.2.6).
A2A_EXTENSIONS_HEADER = "A2A-Extensions"

# Media type of the JWS payload of a secured AAE (AAE -02 section 2.1).
AAE_CTY = "aae+json"

# Profile limits (spec section 11). These are minimum capabilities a verifier
# offers, not ceilings an issuer may rely on beyond.
MAX_ANCESTORS = 16
MAX_JWS_BYTES = 64 * 1024
MAX_CHALLENGE_RESPONSE_BYTES = 8 * 1024
