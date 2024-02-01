from __future__ import annotations

import io
import struct
from datetime import datetime
from functools import cached_property, lru_cache
from typing import BinaryIO, Callable, Iterator, Optional

from dissect.util.stream import AlignedStream, RelativeStream
from dissect.util.ts import wintimestamp

from dissect.archive.c_wim import (
    DECOMPRESSOR_MAP,
    FILE_ATTRIBUTE,
    HEADER_FLAG,
    IO_REPARSE_TAG,
    RESHDR_FLAG,
    SYMLINK_FLAG,
    WIM_IMAGE_TAG,
    c_wim,
)
from dissect.archive.exceptions import (
    FileNotFoundError,
    InvalidHeaderError,
    NotADirectoryError,
    NotAReparsePointError,
)

DEFAULT_CHUNK_SIZE = 32 * 1024


class WIM:
    """"""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_wim.WIMHEADER_V1_PACKED(fh)

        if self.header.ImageTag != WIM_IMAGE_TAG:
            raise InvalidHeaderError("Expected MSWIM header, got: {!r}".format(self.header.ImageTag))

        if self.header.Version != c_wim.VERSION_DEFAULT:
            raise NotImplementedError(f"Only WIM version {c_wim.VERSION_DEFAULT:#x} is supported right now")

        if self.header.Flags & HEADER_FLAG.SPANNED:
            raise NotImplementedError("Spanned WIM files are not yet supported")

        self._resource_table, self._images = self._read_resource_table()

    def _read_resource_table(self) -> tuple[dict[bytes, Resource], list[Resource]]:
        # Read the resource table in one go and separate images out
        # If this turns out to be slow for large WIM files, we can add some clever caching
        table = {}
        images = []
        with Resource.from_short_header(self, self.header.OffsetTable).open() as fh:
            for _ in range(fh.size // len(c_wim._RESHDR_DISK)):
                resource = Resource.from_header(self, c_wim._RESHDR_DISK(fh))
                table[resource.hash] = resource

                if resource.is_metadata:
                    images.append(resource)

        return table, images

    def resources(self) -> Iterator[Resource]:
        """Iterate over all resources in the WIM file."""
        yield from self._resource_table.values()

    def images(self) -> Iterator[Image]:
        """Iterate over all images in the WIM file."""
        for resource in self._images:
            yield Image(self, resource.open())


class Resource:
    __slots__ = ("wim", "size", "flags", "offset", "original_size", "part_number", "reference_count", "hash")

    def __init__(
        self,
        wim: WIM,
        size: int,
        flags: RESHDR_FLAG,
        offset: int,
        original_size: int,
        part_number: Optional[int] = None,
        reference_count: Optional[int] = None,
        hash: Optional[bytes] = None,
    ):
        self.wim = wim
        self.size = size
        self.flags = flags
        self.offset = offset
        self.original_size = original_size

        self.part_number = part_number
        self.reference_count = reference_count
        self.hash = hash

    @classmethod
    def from_short_header(cls, wim: WIM, reshdr: c_wim.RESHDR_DISK_SHORT) -> Resource:
        return cls(
            wim,
            int.from_bytes(reshdr.Size, "little"),
            reshdr.Flags,
            reshdr.Offset,
            reshdr.OriginalSize,
        )

    @classmethod
    def from_header(cls, wim: WIM, reshdr: c_wim.RESHDR_DISK) -> Resource:
        obj = cls.from_short_header(wim, reshdr.Base)
        obj.part_number = reshdr.PartNumber
        obj.reference_count = reshdr.RefCount
        obj.hash = reshdr.Hash
        return obj

    @property
    def is_metadata(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.METADATA)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.COMPRESSED)

    @property
    def is_spanned(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.SPANNED)

    def open(self) -> BinaryIO:
        if self.is_spanned:
            raise NotImplementedError("Spanned resources are not yet supported")

        if self.is_compressed:
            compression_flags = self.wim.header.Flags & 0xFFFF0000
            decompressor = DECOMPRESSOR_MAP.get(compression_flags)
            if decompressor is None:
                raise NotImplementedError(f"Compression algorithm not yet supported: {compression_flags}")
            return CompressedStream(self.wim.fh, self.offset, self.size, self.original_size, decompressor)
        else:
            return RelativeStream(self.wim.fh, self.offset, self.size)


class Image:
    def __init__(self, wim: WIM, fh: BinaryIO):
        self.wim = wim
        self.security = SecurityBlock(fh)

        offset = fh.tell()
        fh.seek(offset + (-offset & 7))
        self.root = DirectoryEntry(self, fh)

    def get(self, path: str, entry: Optional[DirectoryEntry] = None) -> DirectoryEntry:
        # Programmatically we will often use the `/` separator, so replace it with the native path separator of NTFS
        # `/` is an illegal character in NTFS filenames, so it's safe to replace
        search_path = path.replace("/", "\\")

        parts = search_path.split("\\")
        entry = entry or self.root

        for part in parts:
            if not part:
                continue

            # Traverse to the target path from our root node
            for entry in entry.iterdir():
                if entry.name == part:
                    entry = entry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return entry


class SecurityBlock:
    def __init__(self, fh: BinaryIO):
        self.header = c_wim._SECURITYBLOCK_DISK(fh)
        self.descriptors = []
        for size in self.header.EntryLength:
            if size == 0:
                continue

            self.descriptors.append(fh.read(size))


class DirectoryEntry:
    def __init__(self, image: Image, fh: BinaryIO):
        self.image = image
        self.fh = fh

        start = fh.tell()
        self.entry = c_wim._DIRENTRY(fh)
        self.name = None
        self.short_name = None
        self.extra = None

        if length := self.entry.FileNameLength:
            self.name = fh.read(length).decode("utf-16-le")
            fh.read(2)

        if length := self.entry.ShortNameLength:
            self.short_name = fh.read(length).decode("utf-16-le")
            fh.read(2)

        end = fh.tell()
        if (length := self.entry.Length - (((end + 7) & (-8)) - start)) > 0 or (
            length := self.entry.Length - (end - start)
        ) > 0:
            self.extra = fh.read(length)

        self.streams = {}
        if self.entry.Streams:
            for _ in range(self.entry.Streams):
                fh.seek((fh.tell() + 7) & (-8))

                name = ""
                stream = c_wim._STREAMENTRY(fh)
                if name_length := stream.StreamNameLength:
                    name = fh.read(name_length).decode("utf-16-le")
                    name_length += 2
                    fh.read(2)

                self.streams[name] = stream.Hash

                if remaining := stream.Length - len(c_wim._STREAMENTRY) - name_length:
                    fh.read(remaining)
        else:
            # Add the entry hash as the default stream
            self.streams[""] = self.entry.Hash

    def __repr__(self) -> str:
        return f"<DirectoryEntry name={self.name!r}>"

    def is_dir(self) -> bool:
        """Return whether this entry is a directory."""
        return (
            self.entry.Attributes & (FILE_ATTRIBUTE.DIRECTORY | FILE_ATTRIBUTE.REPARSE_POINT)
            == FILE_ATTRIBUTE.DIRECTORY
        )

    def is_file(self) -> bool:
        """Return whether this entry is a regular file."""
        return not self.is_dir()

    def is_reparse_point(self) -> bool:
        """Return whether this entry is a reparse point."""
        return bool(self.entry.Attributes & FILE_ATTRIBUTE.REPARSE_POINT)

    def is_symlink(self) -> bool:
        """Return whether this entry is a symlink reparse point."""
        return self.is_reparse_point() and self.entry.ReparseTag == IO_REPARSE_TAG.SYMLINK

    def is_mount_point(self) -> bool:
        """Return whether this entry is a mount point reparse point."""
        return self.is_reparse_point() and self.entry.ReparseTag == IO_REPARSE_TAG.MOUNT_POINT

    @cached_property
    def reparse_point(self) -> ReparsePoint:
        """Return parsed reparse point data if this directory entry is a reparse point."""
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self} is not a reparse point")

        return ReparsePoint(self.entry.ReparseTag, self.open())

    def size(self, name: str = "") -> int:
        """Return the entry size."""
        with self.open(name) as fh:
            return fh.size

    @cached_property
    def creation_time(self) -> datetime:
        """Return the creation time."""
        return wintimestamp(self.entry.CreationTime)

    @cached_property
    def creation_time_ns(self) -> int:
        """Return the creation time in nanoseconds."""
        return _ts_to_ns(self.entry.CreationTime)

    @cached_property
    def last_access_time(self) -> datetime:
        """Return the last access time."""
        return wintimestamp(self.entry.LastAccessTime)

    @cached_property
    def last_access_time_ns(self) -> int:
        """Return the last access time in nanoseconds."""
        return _ts_to_ns(self.entry.LastAccessTime)

    @cached_property
    def last_write_time(self) -> datetime:
        """Return the last write time."""
        return wintimestamp(self.entry.LastWriteTime)

    @property
    def last_write_time_ns(self) -> int:
        """Return the last write time in nanoseconds."""
        return _ts_to_ns(self.entry.LastWriteTime)

    def listdir(self) -> dict[str, DirectoryEntry]:
        """Return a directory listing."""
        return {entry.name: entry for entry in self.iterdir()}

    def iterdir(self) -> Iterator[DirectoryEntry]:
        """Iterate directory contents."""
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        fh = self.fh
        fh.seek(self.entry.SubdirOffset)
        while True:
            length = int.from_bytes(fh.read(8), "little")
            if length <= 8:
                break

            fh.seek(-8, io.SEEK_CUR)
            yield DirectoryEntry(self.image, fh)

            fh.seek((fh.tell() + 7) & (-8))

    def open(self, name: str = "") -> BinaryIO:
        """Return a file-like object for the contents of this directory entry.

        Args:
            name: Optional alternate stream name to open.
        """
        stream_hash = self.streams.get(name)
        if hash is None:
            raise FileNotFoundError(f"Stream not found in directory entry {self}: {name!r}")

        for resource in self.image.wim.resources():
            if resource.hash == stream_hash:
                return resource.open()
        else:
            raise FileNotFoundError(f"Unable to find resource for directory entry {self}")


class ReparsePoint:
    """Utility class for parsing reparse point buffers.

    Args:
        tag: The type of reparse point to parse.
        fh: A file-like object of the reparse point buffer.
    """

    def __init__(self, tag: IO_REPARSE_TAG, fh: BinaryIO):
        self.tag = tag
        self.info = None

        if tag == IO_REPARSE_TAG.MOUNT_POINT:
            self.info = c_wim._MOUNT_POINT_REPARSE_BUFFER(fh)
        elif tag == IO_REPARSE_TAG.SYMLINK:
            self.info = c_wim._SYMBOLIC_LINK_REPARSE_BUFFER(fh)

        self._buf = fh.read()

    @property
    def substitute_name(self) -> Optional[str]:
        if not self.tag_header:
            return None

        offset = self.info.SubstituteNameOffset
        length = self.info.SubstituteNameLength
        return self._buf[offset : offset + length].decode("utf-16-le")

    @property
    def print_name(self) -> Optional[str]:
        if not self.info:
            return None

        offset = self.info.PrintNameOffset
        length = self.info.PrintNameLength
        return self._buf[offset : offset + length].decode("utf-16-le")

    @property
    def absolute(self) -> bool:
        if self.tag != IO_REPARSE_TAG.SYMLINK:
            return True

        return self.info.Flags == SYMLINK_FLAG.ABSOLUTE

    @property
    def relative(self) -> bool:
        if self.tag != IO_REPARSE_TAG.SYMLINK:
            return False

        return self.info.Flags == SYMLINK_FLAG.RELATIVE


class CompressedStream(AlignedStream):
    def __init__(
        self,
        fh: BinaryIO,
        offset: int,
        compressed_size: int,
        original_size: int,
        decompressor: Callable[[bytes], bytes],
    ):
        self.fh = fh
        self.offset = offset
        self.compressed_size = compressed_size
        self.original_size = original_size
        self.decompressor = decompressor

        # Read the chunk table in advance
        fh.seek(self.offset)
        num_chunks = (original_size + (32 * 1024) - 1) // (32 * 1024) - 1
        if num_chunks == 0:
            self._chunks = (0,)
        else:
            entry_size = "Q" if original_size > 0xFFFFFFFF else "I"
            pattern = f"<{num_chunks}{entry_size}"
            self._chunks = struct.unpack(pattern, fh.read(struct.calcsize(pattern)))

        self._read_chunk = lru_cache(32)(self._read_chunk)
        super().__init__(self.original_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        num_chunks = len(self._chunks)
        chunk, offset_in_chunk = divmod(offset, DEFAULT_CHUNK_SIZE)

        while length:
            if chunk >= num_chunks:
                # We somehow requested more data than we have runs for
                break

            chunk_offset = self._chunks[chunk]
            if chunk < num_chunks - 1:
                next_chunk_offset = self._chunks[chunk + 1]
                chunk_remaining = DEFAULT_CHUNK_SIZE - offset_in_chunk
            else:
                next_chunk_offset = self.compressed_size
                chunk_remaining = (self.original_size - (chunk * DEFAULT_CHUNK_SIZE)) - offset_in_chunk

            read_length = min(chunk_remaining, length)

            buf = self._read_chunk(chunk_offset, next_chunk_offset - chunk_offset)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_length])

            length -= read_length
            offset += read_length
            chunk += 1

        return b"".join(result)

    def _read_chunk(self, offset: int, size: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buf = self.fh.read(size)
        return self.decompressor(buf)


def _ts_to_ns(ts: int) -> int:
    """Convert Windows timestamps to nanosecond timestamps."""
    return (ts * 100) - 11644473600000000000
