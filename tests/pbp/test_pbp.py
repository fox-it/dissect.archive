from __future__ import annotations

import gzip
import hashlib
from io import BytesIO

import pytest

from dissect.archive.exception import FileNotFoundError, InvalidHeaderError
from dissect.archive.pbp.pbp import PBP, SUBFILES
from tests._util import absolute_path


def make_pbp(subfiles: list[bytes]) -> bytes:
    """Create a minimal PBP file with the given subfiles."""
    header = b"\x00PBP" + (1).to_bytes(4, "little")

    offset = len(header) + 8 * 4
    offsets = []
    for subfile in subfiles:
        offsets.append(offset)
        offset += len(subfile)

    header += b"".join(offset.to_bytes(4, "little") for offset in offsets)

    return header + b"".join(subfiles)


def test_pbp_invalid_magic() -> None:
    with pytest.raises(InvalidHeaderError, match=r"^Invalid PBP magic: b'NOPE'$"):
        PBP(BytesIO(b"NOPE" + b"\x00" * 36))


def test_pbp_subfiles() -> None:
    contents = [f"contents {i}".encode() for i in range(len(SUBFILES))]
    pbp = PBP(BytesIO(make_pbp(contents)))

    assert list(pbp.subfiles) == list(SUBFILES)

    for i, name in enumerate(SUBFILES):
        subfile = pbp.get(name)
        assert subfile.name == name
        assert subfile.size == len(contents[i])
        assert subfile.open().read() == contents[i]
        assert pbp.open(name).read() == contents[i]


def test_pbp_partial_subfiles() -> None:
    """Subfiles that share an offset with the next subfile are absent."""
    pbp = PBP(BytesIO(make_pbp([b"", b"ICON0", b"", b"", b"", b"", b"", b"PSAR"])))

    assert list(pbp.subfiles) == ["ICON0.PNG", "DATA.PSAR"]
    assert pbp.open("DATA.PSAR").read() == b"PSAR"


def test_pbp_truncated_subfiles() -> None:
    """Subfiles that point past the end of the file are ignored."""
    header = b"\x00PBP" + (1).to_bytes(4, "little")
    header += b"".join(offset.to_bytes(4, "little") for offset in range(40, 40 + 8 * 4, 4))

    assert not PBP(BytesIO(header)).subfiles


def test_pbp_open_missing_subfile() -> None:
    pbp = PBP(BytesIO(make_pbp([b""] * len(SUBFILES))))

    with pytest.raises(FileNotFoundError, match=r"^Subfile does not exist: ICON0.PNG$"):
        pbp.get("ICON0.PNG")

    with pytest.raises(FileNotFoundError, match=r"^Subfile does not exist: ICON0.PNG$"):
        pbp.open("ICON0.PNG")


def test_pbp_hello_world() -> None:
    """Test reading the subfiles of a real PSP PBP."""
    with gzip.open(absolute_path("_data/pbp/hello.pbp.gz"), "rb") as fh:
        pbp = PBP(fh)

        assert set(pbp.subfiles.keys()) == {"PARAM.SFO", "ICON0.PNG", "PIC1.PNG", "DATA.PSP", "DATA.PSAR"}
        assert pbp.subfiles["DATA.PSAR"].size == 163696

        assert pbp.open("PARAM.SFO").read(8) == b"\x00PSF\x01\x01\x00\x00"
        assert pbp.open("ICON0.PNG").read(8) == b"\x89PNG\r\n\x1a\n"
        assert (
            hashlib.sha256(pbp.open("DATA.PSP").read()).hexdigest()
            == "59b460f8f26cd14c392fdd3bd1b6b919c712b9ba0836ba9a881ac003d4f3e781"
        )
