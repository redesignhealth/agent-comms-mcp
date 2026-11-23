"""Encryption of wake target secrets at rest (TECH-9908).

Fernet (AES-128-CBC + HMAC-SHA256, from ``cryptography``, already in the
dependency tree through authlib) keyed by the operator setting
``WAKE_TARGET_SECRET_KEY``: a urlsafe-base64 encoded 32-byte key, as produced by
``python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"``.

``encrypt_secret`` is used when a wake target is registered. ``decrypt_secret``
is for the delivery task, which needs the plaintext to sign events. Both fail
closed: a missing or malformed key raises ``WakeTargetMisconfiguredError``.
Nothing here logs or echoes a secret, a ciphertext or the key.
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.fernet import Fernet, InvalidToken

from exceptions import WakeTargetMisconfiguredError

WAKE_TARGET_SECRET_KEY_ENV_VAR: Final = "WAKE_TARGET_SECRET_KEY"


def _fernet() -> Fernet:
    key = os.environ.get(WAKE_TARGET_SECRET_KEY_ENV_VAR, "").strip()
    if not key:
        raise WakeTargetMisconfiguredError(
            f"{WAKE_TARGET_SECRET_KEY_ENV_VAR} is not set, so wake targets cannot be stored"
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise WakeTargetMisconfiguredError(
            f"{WAKE_TARGET_SECRET_KEY_ENV_VAR} is not a valid Fernet key "
            "(urlsafe base64 of 32 bytes)"
        ) from None


def encrypt_secret(secret: str) -> bytes:
    """Encrypt a wake target secret for storage in ``wake_targets.secret_ciphertext``."""
    return _fernet().encrypt(secret.encode("utf-8"))


def decrypt_secret(ciphertext: bytes) -> str:
    """Return the plaintext secret for ``ciphertext``.

    Raises ``WakeTargetMisconfiguredError`` if the key is missing or malformed, or
    if the ciphertext was not produced with the current key.
    """
    try:
        return _fernet().decrypt(ciphertext).decode("utf-8")
    except InvalidToken:
        raise WakeTargetMisconfiguredError(
            f"stored wake target secret cannot be decrypted with the current "
            f"{WAKE_TARGET_SECRET_KEY_ENV_VAR}"
        ) from None


__all__ = ["WAKE_TARGET_SECRET_KEY_ENV_VAR", "decrypt_secret", "encrypt_secret"]
