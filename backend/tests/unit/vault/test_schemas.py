"""Unit tests для vault schemas helpers (#203).

Покрывает `_decode_b64` — security-relevant validator, который
Pydantic вызывает на каждый ciphertext field setup/unlock/create.
Слабый или missing validation → 422 → DoS (huge payload) или
crash. Regression guard важнее, чем для среднего helper'а.
"""

from base64 import b64encode

import pytest

from src.api.vault.schemas import _decode_b64


def test_decode_b64_valid_input() -> None:
    raw = b"hello world"
    encoded = b64encode(raw).decode("ascii")
    assert _decode_b64(encoded, max_len=100, field_name="test") == raw


def test_decode_b64_at_max_length_passes() -> None:
    """Boundary: len(decoded) == max_len → принимается."""
    raw = b"x" * 32
    encoded = b64encode(raw).decode("ascii")
    assert _decode_b64(encoded, max_len=32, field_name="test") == raw


def test_decode_b64_exceeds_max_length_rejects() -> None:
    raw = b"x" * 33
    encoded = b64encode(raw).decode("ascii")
    with pytest.raises(ValueError, match="exceeds 32 bytes"):
        _decode_b64(encoded, max_len=32, field_name="my_field")


def test_decode_b64_empty_after_decode_rejects() -> None:
    """Empty string b64 → empty bytes → reject (anti-zero-length attack)."""
    with pytest.raises(ValueError, match="empty after decode"):
        _decode_b64("", max_len=100, field_name="payload")


def test_decode_b64_malformed_rejects() -> None:
    """Non-base64 chars → ValueError с polite message (не leak'аем underlying error)."""
    with pytest.raises(ValueError, match="malformed base64"):
        _decode_b64("!!!not-valid-b64!!!", max_len=100, field_name="key")


def test_decode_b64_message_includes_field_name() -> None:
    """Error message contains `field_name` для отладки клиентского кода."""
    with pytest.raises(ValueError, match="auth_hash_b64") as exc_info:
        _decode_b64("!!", max_len=100, field_name="auth_hash_b64")
    assert "auth_hash_b64" in str(exc_info.value)


def test_decode_b64_padding_required() -> None:
    """validate=True требует canonical padding — incomplete b64 → reject."""
    # "abc" в b64 = "YWJj", "ab" = "YWI=" (padded). Без = должно reject.
    with pytest.raises(ValueError, match="malformed base64"):
        _decode_b64("YWI", max_len=100, field_name="x")
