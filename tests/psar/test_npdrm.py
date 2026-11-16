from __future__ import annotations

import hashlib

import pytest

from dissect.archive.psar import npdrm

pytestmark = pytest.mark.skipif(not npdrm.HAS_PYCRYPTODOME, reason="No crypto module available")

# Reference values from the sceDrmBB* implementation of libkirk, as used by sign_np and PPSSPP
HEADER = bytes.fromhex(
    "4e50554d44494d473a424950585f666e757c848b929aa1a8b0b7bec6cdd4dce3eaf2f900080f161e252c343b424a"
    "515860676e767d848c939aa2a9b0b8bfc6ced5dce4ebf2fa010810171e262d343c434a525960686f767e858c949b"
    "a2aab1b8c0c7ced6dde4ecf3fa020910181f262e353c444b525a616870777e868d949ca3aab2b9c0c8cfd6dee5ec"
    "f4fb020a111820272e363d444c535a626970787f868e959ca4abb2bac1c8d0d7dee6edf4fc030a121920282f363e"
    "454c545b626a717880878e969da4acb3bac2c9d0d8dfe6eef5fc040b121a212830373e464d545c636a727980888f"
    "969ea5acb4bbc2cad1d8e0e7eef6fd040c131a222930383f464e"
)
HEADER_KEY = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
VERSION_KEY = bytes.fromhex("38cffceb6c84b7e597c2663841384780")

DATA = bytes((i * 31 + 7) & 0xFF for i in range(0x900))


def test_derive_version_key() -> None:
    assert npdrm.derive_version_key(HEADER[:0xC0], HEADER[0xC0:0xD0]) == VERSION_KEY


@pytest.mark.parametrize(
    ("seed", "digest"),
    [
        (0, "d49b0d9199e681b8c0fc1765468973d19c2c2a6422c0570fcb0d9cfc11e24214"),
        (0x10, "0fdcd008bdbb2abfe8b62db47f7b4385491345413b6f1c6162da7400705d5679"),
    ],
)
def test_decrypt(seed: int, digest: str) -> None:
    """Test decrypting data that is larger than the 0x800 bytes that libkirk decrypts at once."""
    assert hashlib.sha256(npdrm.decrypt(DATA, HEADER_KEY, VERSION_KEY, seed)).hexdigest() == digest


def test_missing_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test whether a missing pycryptodome is reported."""
    monkeypatch.setattr(npdrm, "HAS_PYCRYPTODOME", False)

    message = r"^Missing pycryptodome dependency for NPDRM support: install dissect.archive\[full\]$"
    with pytest.raises(RuntimeError, match=message):
        npdrm.derive_version_key(HEADER[:0xC0], HEADER[0xC0:0xD0])

    with pytest.raises(RuntimeError, match=message):
        npdrm.decrypt(DATA, HEADER_KEY, VERSION_KEY)
