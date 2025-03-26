from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with absolute_path(name).open(mode) as f:
        yield f


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def basic_wim() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/basic.wim.gz")


@pytest.fixture
def test4k_wim() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/test4k.wim.gz")


@pytest.fixture
def test8k_wim() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/test8k.wim.gz")


@pytest.fixture
def test16k_wim() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/test16k.wim.gz")


@pytest.fixture
def basic_vma() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/test.vma.gz")


@pytest.fixture
def vbk9() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/test9.vbk.gz")


@pytest.fixture
def vbk13() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/test13.vbk.gz")
