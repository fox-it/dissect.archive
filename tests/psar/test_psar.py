from __future__ import annotations

import gzip
import hashlib
from io import BytesIO

import pytest
from dissect.util.compression import lzrc

from dissect.archive.exception import InvalidHeaderError
from dissect.archive.pbp.pbp import PBP
from dissect.archive.psar import npdrm
from dissect.archive.psar.c_psar import c_psar
from dissect.archive.psar.psar import LBA_SIZE, PSAR, PSARError
from tests._util import absolute_path

pytestmark = pytest.mark.skipif(not npdrm.HAS_PYCRYPTODOME, reason="No crypto module available")

BLOCK_LBAS = 2
BLOCK_SIZE = BLOCK_LBAS * LBA_SIZE
LBA_START = 4
TABLE_OFFSET = 0x100

HEADER_KEY = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
VERSION_KEY = bytes.fromhex("38cffceb6c84b7e597c2663841384780")
CONTENT_ID = b"UP0000-NPDEMO001_00-0000000000000000"
DISC_ID = b"NPDE-MO001"

ENCRYPTED = c_psar.BlockFlags(0)
UNENCRYPTED = c_psar.BlockFlags.UNENCRYPTED

BLOCKS = [bytes([i]) * LBA_SIZE + bytes([i + 0x10]) * LBA_SIZE for i in range(3)]
COMPRESSED = lzrc.compress(BLOCKS[2])

# The UMD image in the "hello world" PBP fixture and its NPDRM fixed key, as reported by
# tests/_tools/pbp/generate.sh
HELLO_ISO_SIZE = 528384
HELLO_ISO_SHA256 = "0e9e4767264fe4c53406cf8dd968ef48fdc5d2067af571d1a3bd96fb4fde9712"
HELLO_VERSION_KEY = bytes.fromhex("fef2d3cc16aa0b6bd1ec5a60d9afae18")


def make_mac(data: bytes) -> bytes:
    """Create the BBMac of data with the version key, the inverse of :func:`npdrm.derive_version_key`."""
    from Crypto.Cipher import AES

    mac = AES.new(npdrm.KEYVAULT_38, AES.MODE_ECB).encrypt(npdrm._xor(npdrm._mac(data), VERSION_KEY))
    return AES.new(npdrm.KEYVAULT_63, AES.MODE_ECB).encrypt(mac)


def make_psar(
    blocks: list[tuple[bytes | None, c_psar.BlockFlags]],
    block_lbas: int = BLOCK_LBAS,
    lba_start: int = LBA_START,
    lba_end: int | None = None,
) -> BytesIO:
    """Create a NPUMDIMG image, with the block table directly after the header like sign_np does.

    Args:
        blocks: The stored data and the flags of each block, a block without data is not stored.
        block_lbas: The amount of LBAs in a block.
        lba_start: The first LBA of the image.
        lba_end: The last LBA of the image, defaults to the end of the last block.
    """
    table = b""
    data = b""
    offset = TABLE_OFFSET + len(blocks) * len(c_psar.Block)

    for i, (block, flags) in enumerate(blocks):
        # The MAC is not verified, but it has to differ per word for the entry to be scrambled
        mac = bytes(range(i * 16, i * 16 + 16))
        entry = c_psar.Block(mac=mac, offset=0, size=0, flags=flags, unk_1c=int(block is None))
        if block is not None:
            if not flags & UNENCRYPTED:
                # The cipher XORs the data with a keystream, so encrypting is the same as decrypting
                block = npdrm.decrypt(block, HEADER_KEY, VERSION_KEY, offset >> 4)

            entry.offset = offset
            entry.size = len(block)
            data += block
            offset += len(block)

        m0, m1, m2, m3 = c_psar.uint32[4](entry.mac)
        entry.offset ^= m2 ^ m3
        entry.size ^= m1 ^ m2
        entry.flags ^= m0 ^ m3
        entry.unk_1c ^= m0 ^ m1
        table += entry.dumps()

    if lba_end is None:
        lba_end = lba_start + len(blocks) * block_lbas - 1

    body = c_psar.HeaderBody(
        sector_size=LBA_SIZE,
        lba_start=lba_start,
        lba_end=lba_end,
        table_offset=TABLE_OFFSET,
        disc_id=DISC_ID,
    )
    header = c_psar.Header(
        magic=b"NPUMDIMG",
        np_flags=0x2,
        block_lbas=block_lbas,
        content_id=CONTENT_ID,
        body=npdrm.decrypt(body.dumps(), HEADER_KEY, VERSION_KEY),
        header_key=HEADER_KEY,
    ).dumps()
    header = header[:0xC0] + make_mac(header[:0xC0]) + header[0xD0:]

    return BytesIO(header + table + data)


@pytest.fixture
def psar() -> PSAR:
    return PSAR(
        make_psar(
            [
                (BLOCKS[0], ENCRYPTED),
                (BLOCKS[1], UNENCRYPTED),
                (COMPRESSED, ENCRYPTED),
                (None, ENCRYPTED),
            ]
        )
    )


def test_psar_header(psar: PSAR) -> None:
    assert psar.header.np_flags == 0x2
    assert psar.header.block_lbas == BLOCK_LBAS
    assert psar.header.content_id == CONTENT_ID
    assert psar.header.header_key == HEADER_KEY
    assert psar.version_key == VERSION_KEY

    assert psar.body.sector_size == LBA_SIZE
    assert psar.body.lba_start == LBA_START
    assert psar.body.lba_end == LBA_START + 8 - 1
    assert psar.body.table_offset == TABLE_OFFSET
    assert psar.body.disc_id == DISC_ID.ljust(0x10, b"\x00")

    assert psar.block_size == BLOCK_SIZE
    assert psar.size == 8 * LBA_SIZE
    assert psar.num_blocks == 4


def test_psar_table(psar: PSAR) -> None:
    offset = TABLE_OFFSET + 4 * len(c_psar.Block)

    assert [(block.offset, block.size, block.flags, block.unk_1c) for block in psar.table] == [
        (offset, BLOCK_SIZE, ENCRYPTED, 0),
        (offset + BLOCK_SIZE, BLOCK_SIZE, UNENCRYPTED, 0),
        (offset + 2 * BLOCK_SIZE, len(COMPRESSED), ENCRYPTED, 0),
        (0, 0, ENCRYPTED, 1),
    ]


def test_psar_read_block(psar: PSAR) -> None:
    """Test reading encrypted, unencrypted, compressed and absent blocks."""
    assert [psar.read_block(i) for i in range(psar.num_blocks)] == [*BLOCKS, b"\x00" * BLOCK_SIZE]


@pytest.mark.parametrize("index", [4, -1])
def test_psar_read_block_out_of_range(psar: PSAR, index: int) -> None:
    with pytest.raises(IndexError, match=r"^Block index out of range$"):
        psar.read_block(index)


@pytest.mark.parametrize(
    ("blocks", "message"),
    [
        ([(b"A" * (BLOCK_SIZE + 16), UNENCRYPTED)], r"^Invalid block size for block 0: 4112$"),
        ([(None, ENCRYPTED), (BLOCKS[0], ENCRYPTED)], r"^Block 0 is not stored$"),
        ([(lzrc.compress(b"A" * 100), ENCRYPTED)], r"^Failed to decompress block 0$"),
    ],
)
def test_psar_read_block_invalid(blocks: list[tuple[bytes | None, c_psar.BlockFlags]], message: str) -> None:
    with pytest.raises(PSARError, match=message):
        PSAR(make_psar(blocks)).read_block(0)


def test_psar_read_block_truncated() -> None:
    fh = make_psar([(BLOCKS[0], ENCRYPTED)])
    fh.truncate(TABLE_OFFSET + len(c_psar.Block) + 1024)

    with pytest.raises(PSARError, match=r"^Block 0 extends past the end of the image$"):
        PSAR(fh).read_block(0)


def test_psar_stream(psar: PSAR) -> None:
    image = b"".join(BLOCKS) + b"\x00" * BLOCK_SIZE

    stream = psar.open()
    assert stream.read() == image

    # A read that spans multiple blocks
    stream.seek(LBA_SIZE + 1000)
    assert stream.read(2 * BLOCK_SIZE) == image[LBA_SIZE + 1000 : LBA_SIZE + 1000 + 2 * BLOCK_SIZE]


@pytest.mark.parametrize(
    ("magic", "message"),
    [
        (b"INVALID!", r"^Invalid PSAR magic: b'INVALID!'$"),
        (b"PSISOIMG", r"^PS1 PSAR image is not supported$"),
    ],
)
def test_psar_invalid_magic(magic: bytes, message: str) -> None:
    fh = make_psar([(BLOCKS[0], ENCRYPTED)])
    fh.write(magic)

    with pytest.raises(InvalidHeaderError, match=message):
        PSAR(fh)


@pytest.mark.parametrize(
    ("lba_start", "lba_end", "block_lbas", "message"),
    [
        (10, 5, BLOCK_LBAS, r"^Invalid LBA range in header$"),
        (0, 10, 0, r"^Invalid amount of LBAs in a block: 0$"),
        (0, 10, 4097, r"^Invalid amount of LBAs in a block: 4097$"),
    ],
)
def test_psar_invalid_header(lba_start: int, lba_end: int, block_lbas: int, message: str) -> None:
    fh = make_psar([(BLOCKS[0], ENCRYPTED)], block_lbas=block_lbas, lba_start=lba_start, lba_end=lba_end)

    with pytest.raises(InvalidHeaderError, match=message):
        PSAR(fh)


def test_psar_hello_world() -> None:
    """Test reading the NPUMDIMG image of a PSN EBOOT.PBP that is generated with sign_np."""
    with gzip.open(absolute_path("_data/pbp/hello.pbp.gz"), "rb") as fh:
        psar = PSAR(PBP(fh).open("DATA.PSAR"))

        assert psar.header.np_flags == 0x01000003
        assert psar.header.content_id == b"UP0000-NPUZ00001_00-DISSECTHELLO0001"
        assert psar.version_key == HELLO_VERSION_KEY
        assert psar.body.disc_id == b"NPUZ-00001".ljust(0x10, b"\x00")
        assert psar.block_size == 0x8000

        # sign_np stores whole blocks, so the image ends in the padding of the last block
        assert psar.num_blocks == 17
        assert psar.size == psar.num_blocks * psar.block_size

        # All blocks are stored and encrypted, and only compressed if that saves enough space, which is not
        # the case for the blocks of the (already encrypted) EBOOT.BIN
        assert all(block.flags == ENCRYPTED and not block.unk_1c for block in psar.table)
        assert any(block.size < psar.block_size for block in psar.table)
        assert any(block.size == psar.block_size for block in psar.table)

        image = psar.open().read()
        assert hashlib.sha256(image[:HELLO_ISO_SIZE]).hexdigest() == HELLO_ISO_SHA256
        assert image[HELLO_ISO_SIZE:] == b"\x00" * (psar.size - HELLO_ISO_SIZE)
