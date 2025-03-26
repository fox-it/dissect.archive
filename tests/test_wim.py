from __future__ import annotations

import hashlib
from typing import BinaryIO

import pytest

from dissect.archive.wim import WIM


@pytest.mark.parametrize(
    ("fixture", "chunk_size"),
    [
        ("basic_wim", 0x8000),
        ("test4k_wim", 0x1000),
        ("test8k_wim", 0x2000),
        ("test16k_wim", 0x4000),
    ],
)
def test_wim(fixture: BinaryIO, chunk_size: int, request: pytest.FixtureRequest) -> None:
    value = request.getfixturevalue(fixture)
    wim = WIM(value)

    assert wim.header.CompressionSize == chunk_size

    images = list(wim.images())
    assert len(images) == 1

    image = images[0]
    assert sorted(image.root.listdir().keys()) == ["ads.txt", "dir", "file.txt", "link.txt"]

    entry = image.get("file.txt")
    assert entry.is_file()
    assert not entry.is_dir()
    assert not entry.is_reparse_point()
    assert len(entry.streams) == 1
    assert entry.size() == 70
    assert hashlib.sha1(entry.open().read()).hexdigest() == "0aaa8266648364d68b67be77c53f708a77fda84c"

    entry = image.get("ads.txt")
    assert entry.is_file()
    assert not entry.is_dir()
    assert not entry.is_reparse_point()
    assert len(entry.streams) == 2
    assert entry.size() == 30
    assert entry.size("spookystream") == 38
    assert hashlib.sha1(entry.open().read()).hexdigest() == "8e2dbd4ff0c5e125b445ded476f5bb9637e115a6"
    assert hashlib.sha1(entry.open("spookystream").read()).hexdigest() == "0fb3109183dc351670bec54bebe6406ad016315e"

    entry = image.get("link.txt")
    assert entry.is_file()
    assert not entry.is_dir()
    assert entry.is_reparse_point()
    assert entry.is_mount_point()
    assert entry.reparse_point.print_name == "C:\\dir\\another.txt"

    entry = image.get("dir")
    assert not entry.is_file()
    assert entry.is_dir()
    assert not entry.is_reparse_point()
    assert sorted(entry.listdir().keys()) == ["another.txt"]

    entry = image.get("dir/another.txt")
    assert entry.is_file()
    assert not entry.is_dir()
    assert not entry.is_reparse_point()
    assert len(entry.streams) == 1
    assert entry.size() == 60
    assert hashlib.sha1(entry.open().read()).hexdigest() == "1fc83a896287fe48f6d42d8d04f88f6dc90c0c45"
