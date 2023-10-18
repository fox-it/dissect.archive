import gzip
import os
from typing import BinaryIO, Iterator

import pytest


def absolute_path(filename) -> str:
    return os.path.join(os.path.dirname(__file__), filename)


def open_file(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with open(absolute_path(name), mode) as f:
        yield f


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def basic_wim() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/basic.wim.gz")
