# References:
# - https://github.com/hrydgard/ppsspp/blob/master/Core/FileSystems/BlockDevices.cpp
# - https://github.com/swarzesherz/sign_np/blob/master/sign_np.c
# - https://github.com/LunaMoo/iPBP/blob/main/src/convert.cpp
from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.compression import lzrc
from dissect.util.stream import AlignedStream

from dissect.archive.exception import Error, InvalidHeaderError
from dissect.archive.psar import npdrm
from dissect.archive.psar.c_psar import c_psar

if TYPE_CHECKING:
    from dissect.cstruct import Structure


PSAR_MAGIC = b"NPUMDIMG"
PSAR_MAGIC_PS1 = b"PSISOIMG"
LBA_SIZE = 2048
MAX_BLOCK_LBAS = 4096


class PSARError(Error):
    pass


class PSAR:
    """Sony PSP NPDRM UMD (NPUMDIMG) image implementation.

    A NPUMDIMG image is the ``DATA.PSAR`` of a PSN ``EBOOT.PBP``, and stores a UMD (ISO 9660) image in
    blocks that are optionally compressed with :func:`dissect.util.compression.lzrc` and encrypted with
    NPDRM. The image starts with a header and a block table, which are followed by the blocks.

    Args:
        fh: The file-like object of the NPUMDIMG image to read.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        fh.seek(0)
        self.header = c_psar.Header(fh)

        if self.header.magic == PSAR_MAGIC_PS1:
            raise InvalidHeaderError("PS1 PSAR image is not supported")

        if self.header.magic != PSAR_MAGIC:
            raise InvalidHeaderError(f"Invalid PSAR magic: {self.header.magic!r}")

        # The version key is not stored, but is recovered from the MAC of the first 0xc0 bytes of the header
        self.version_key = npdrm.derive_version_key(self.header.dumps()[:0xC0], self.header.header_mac)
        self.body = c_psar.HeaderBody(npdrm.decrypt(self.header.body, self.header.header_key, self.version_key))

        if not 0 < self.header.block_lbas <= MAX_BLOCK_LBAS:
            raise InvalidHeaderError(f"Invalid amount of LBAs in a block: {self.header.block_lbas}")

        if self.body.lba_end < self.body.lba_start:
            raise InvalidHeaderError("Invalid LBA range in header")

        self.block_size = self.header.block_lbas * LBA_SIZE
        self.size = (self.body.lba_end - self.body.lba_start + 1) * LBA_SIZE
        self.num_blocks = (self.size + self.block_size - 1) // self.block_size

    @cached_property
    def table(self) -> list[Structure]:
        """The block table of this image."""
        self.fh.seek(self.body.table_offset)
        table = c_psar.Block[self.num_blocks](self.fh)

        for block in table:
            # The fields of a block entry are scrambled with the MAC that is stored in it
            m0, m1, m2, m3 = c_psar.uint32[4](block.mac)
            block.offset ^= m2 ^ m3
            block.size ^= m1 ^ m2
            block.flags = c_psar.BlockFlags(block.flags ^ m0 ^ m3)
            block.unk_1c ^= m0 ^ m1

        return table

    def read_block(self, index: int) -> bytes:
        """Read a single block from the image.

        Args:
            index: The index of the block to read.
        """
        if not 0 <= index < self.num_blocks:
            raise IndexError("Block index out of range")

        block = self.table[index]
        if block.unk_1c:
            # Only the last block can be absent, which happens in images made by fake_np
            if index != self.num_blocks - 1:
                raise PSARError(f"Block {index} is not stored")
            return b"\x00" * self.block_size

        if block.size > self.block_size:
            raise PSARError(f"Invalid block size for block {index}: {block.size}")

        self.fh.seek(block.offset)
        data = self.fh.read(block.size)

        if len(data) != block.size:
            raise PSARError(f"Block {index} extends past the end of the image")

        if not block.flags & c_psar.BlockFlags.UNENCRYPTED:
            data = npdrm.decrypt(data, self.header.header_key, self.version_key, block.offset >> 4)

        if block.size < self.block_size:
            data = lzrc.decompress(data, self.block_size)
            if len(data) != self.block_size:
                raise PSARError(f"Failed to decompress block {index}")

        return data

    def open(self) -> PSARStream:
        """Open the stored UMD image for reading."""
        return PSARStream(self)


class PSARStream(AlignedStream):
    """Stream of the UMD image that is stored in a :class:`PSAR`.

    Args:
        psar: The NPUMDIMG image to read from.
    """

    def __init__(self, psar: PSAR):
        self.psar = psar
        super().__init__(psar.size, psar.block_size)

    def _read(self, offset: int, length: int) -> bytes:
        block_size = self.psar.block_size
        return b"".join(self.psar.read_block(i) for i in range(offset // block_size, (offset + length) // block_size))
