# References:
# - https://github.com/hrydgard/ppsspp/blob/master/Core/ELF/PBPReader.cpp
from __future__ import annotations

import io
from functools import cached_property
from typing import BinaryIO

from dissect.util.stream import RangeStream

from dissect.archive.exception import FileNotFoundError, InvalidHeaderError
from dissect.archive.pbp.c_pbp import c_pbp

MAGIC = b"\x00PBP"

SUBFILES = (
    "PARAM.SFO",
    "ICON0.PNG",
    "ICON1.PMF",
    "PIC0.PNG",
    "PIC1.PNG",
    "SND0.AT3",
    "DATA.PSP",
    "DATA.PSAR",
)


class PBP:
    """Sony PSP Boot Package (PBP) file implementation.

    A PBP stores up to eight subfiles: the metadata (PARAM.SFO), the icons, backgrounds and sound that the XMB
    shows (ICON0.PNG, ICON1.PMF, PIC0.PNG, PIC1.PNG, SND0.AT3), the executable (DATA.PSP) and an archive
    (DATA.PSAR). The DATA.PSAR of a PSN ``EBOOT.PBP`` is a UMD image, see :class:`dissect.archive.psar.PSAR`.

    Args:
        fh: The file-like object of the PBP file to read.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        fh.seek(0)
        self.header = c_pbp.PBPHeader(fh)

        if self.header.magic != MAGIC:
            raise InvalidHeaderError(f"Invalid PBP magic: {self.header.magic!r}")

    @cached_property
    def subfiles(self) -> dict[str, SubFile]:
        """The subfiles of this PBP, keyed on their name."""
        self.fh.seek(0, io.SEEK_END)
        size = self.fh.tell()

        subfiles = {}
        for i, name in enumerate(SUBFILES):
            start = self.header.offsets[i]
            end = self.header.offsets[i + 1] if i + 1 < len(SUBFILES) else size

            # Subfiles are optional, an absent subfile shares its offset with the next one
            if not start < end <= size:
                continue

            subfiles[name] = SubFile(self, name, start, end - start)

        return subfiles

    def get(self, name: str) -> SubFile:
        """Return a subfile by name.

        Args:
            name: The name of the subfile to return.

        Raises:
            FileNotFoundError: If the subfile does not exist in this PBP.
        """
        try:
            return self.subfiles[name]
        except KeyError:
            raise FileNotFoundError(f"Subfile does not exist: {name}") from None

    def open(self, name: str) -> RangeStream:
        """Open a subfile for reading.

        Args:
            name: The name of the subfile to open.
        """
        return self.get(name).open()


class SubFile:
    """A single subfile of a :class:`PBP` file.

    Args:
        pbp: The PBP file this subfile is part of.
        name: The name of this subfile.
        offset: The offset of this subfile in the PBP file.
        size: The size of this subfile.
    """

    def __init__(self, pbp: PBP, name: str, offset: int, size: int):
        self.pbp = pbp
        self.name = name
        self.offset = offset
        self.size = size

    def __repr__(self) -> str:
        return f"<SubFile name={self.name!r} offset={self.offset} size={self.size}>"

    def open(self) -> RangeStream:
        """Open this subfile for reading."""
        return RangeStream(self.pbp.fh, self.offset, self.size)
