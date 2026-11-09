# References:
# - https://github.com/swarzesherz/sign_np/blob/master/libkirk/amctrl.c
# - https://github.com/hrydgard/ppsspp/blob/master/ext/libkirk/amctrl.c
from __future__ import annotations

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# AES keys 0x38, 0x39 and 0x63 of the KIRK key vault
KEYVAULT_38 = bytes.fromhex("12468d7e1c42209bba5426835eb03303")
KEYVAULT_39 = bytes.fromhex("c43bb6d653ee67493ea95fbc0ced6f8a")
KEYVAULT_63 = bytes.fromhex("9c9b1372f8c640cf1c62f5d592ddb582")

# Fixed XOR masks of the MAC and of the cipher key, amctrl_key1, amctrl_key3 and amctrl_key2 in libkirk
MAC_MASK = bytes.fromhex("e350ed1d910a1fd029bb1c3ef34077fb")
KEY_MASK_IN = bytes.fromhex("678d7fa32a9ca0d1508ad8385e4b017e")
KEY_MASK_OUT = bytes.fromhex("135fa47cab395ba476b8cca98f3a0445")


def derive_version_key(data: bytes, mac: bytes) -> bytes:
    """Recover the version key from a type 3 BBMac.

    A BBMac is the AES-CMAC of the data, which is encrypted together with the version key. The
    version key therefore follows from the data and its BBMac (``bbmac_getkey`` in libkirk).

    Args:
        data: The data that the BBMac is calculated over.
        mac: The BBMac of the data.

    Raises:
        RuntimeError: If no crypto module is available.
    """
    _check_crypto()
    return _xor(_mac(data), _decrypt_block(KEYVAULT_38, _decrypt_block(KEYVAULT_63, mac)))


def decrypt(data: bytes, header_key: bytes, version_key: bytes, seed: int = 0) -> bytes:
    """Decrypt data that is encrypted with a type 1 BBCipher.

    The data is XORed with a keystream of 16 byte blocks. Each block is the AES-CBC decryption of a
    counter: 12 bytes derived from the header key and version key, followed by the 32-bit block number.
    The first block number is the seed plus one, so data that is encrypted at an offset in a file
    can use the offset divided by 16 as the seed.

    Args:
        data: The data to decrypt.
        header_key: The header key of the NPUMDIMG header.
        version_key: The version key of the NPUMDIMG header.
        seed: The block number before the first block of the data.

    Raises:
        RuntimeError: If no crypto module is available.
    """
    _check_crypto()

    prefix = _xor(_decrypt_block(KEYVAULT_39, _xor(_xor(header_key, version_key), KEY_MASK_IN)), KEY_MASK_OUT)[:12]
    counters = b"".join(prefix + (seed + i).to_bytes(4, "little") for i in range(1, (len(data) + 15) // 16 + 1))
    # The initialization vector continues the counters, except at the start of the data
    iv = prefix + seed.to_bytes(4, "little") if seed else b"\x00" * 16
    keystream = AES.new(KEYVAULT_63, AES.MODE_CBC, iv).decrypt(counters)

    return _xor(data, keystream[: len(data)])


def _mac(data: bytes) -> bytes:
    """Calculate the BBMac of data before it is encrypted with the version key."""
    return _xor(CMAC.new(KEYVAULT_38, data, ciphermod=AES).digest(), MAC_MASK)


def _decrypt_block(key: bytes, block: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(block)


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).to_bytes(len(a), "little")


def _check_crypto() -> None:
    if not HAS_PYCRYPTODOME:
        raise RuntimeError("Missing pycryptodome dependency for NPDRM support: install dissect.archive[full]")
