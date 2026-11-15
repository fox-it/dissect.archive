from __future__ import annotations

import io
import uuid

import pytest

from dissect.archive.tibx.c_tibx import c_tibx
from dissect.archive.tibx.exception import InvalidArchiveError
from dissect.archive.tibx.tibx import TIBX, RecoveryPoint
from tests._tools.tibx._synth import (
    PAGE,
    Cell,
    ExtentSpec,
    build_lsm_archive,
    lsb,
    lsm_page,
    slice_record,
)

# A chain lives in one archive: each backup writes its extents under its own slice id, and
# the slices tree (TLV[5]) records the backups. Slice ids are not contiguous in the wild --
# a real differential chain numbered its two backups 2 and 4 -- so this uses 2, 3, 5.
SLICES = [2, 3, 5]


def _chain() -> TIBX:
    archive = build_lsm_archive(
        [
            ExtentSpec(10, 0, b"base state" + b"\x00" * 54, slice_id=2),
            ExtentSpec(10, 0, b"after first backup" + b"\x00" * 46, slice_id=3),
            ExtentSpec(10, 0, b"after second backup" + b"\x00" * 45, slice_id=5),
        ],
        slices=SLICES,
    )
    return TIBX(io.BytesIO(archive))


# The flags of each kind of slice seen in real archives; see SliceFlags
FULL = 0x01
INCREMENTAL = 0x06
# A differential backup right after a full one, written as an incremental
DIFFERENTIAL = 0x0A
# A slice written as a differential, which Acronis hides
HIDDEN = 0x0B

# Records of the kinds real archives hold besides their backups, as (slice id, flags, finish
# time in ms, GUID): a hidden record seconds before a differential backup, and a full backup
# that Acronis deleted, with the GUID of the one that replaced it and has not finished
RESTARTED = b"\x66" * 16
RECORDS = [
    (2, FULL, 2010, b"\x02" * 16),
    (3, HIDDEN, 3010, b"\x03" * 16),
    (4, DIFFERENTIAL, 4010, b"\x04" * 16),
    (5, c_tibx.SliceFlags.DELETED | FULL, 5010, RESTARTED),
    (6, FULL, 0, RESTARTED),
]


def _with_records(records: list[tuple[int, int, int, bytes]], slice_ids: list[int] | None = None) -> TIBX:
    """An archive of ``records``, whose slices each write ``slice <id>`` at the start of a stream."""
    if slice_ids is None:
        slice_ids = [slice_id for slice_id, *_ in records]
    extents = [
        ExtentSpec(10, 0, f"slice {slice_id}".encode().ljust(64, b"\x00"), slice_id=slice_id) for slice_id in slice_ids
    ]
    cells = [
        Cell(c_tibx.slice_key(slice_id=slice_id).dumps(), slice_record(guid, 1000 * slice_id, finished, flags))
        for slice_id, flags, finished, guid in records
    ]
    slices = lsb(4, len(c_tibx.slice_record), memtree_cells=cells)
    return TIBX(io.BytesIO(build_lsm_archive(extents, extra_slots={5: slices})))


def test_slice_record_size() -> None:
    # Ensure that the slice_record struct remains correct size
    assert len(c_tibx.slice_record) == 0x84


def test_recovery_points_are_backups_not_commit_roots() -> None:
    # Acronis writes a varying number of ARCH commit roots per backup, so counting roots
    # invents recovery points that were never taken. The slices tree is the archive's own
    # record of its backups, and matches what "acrocmd list backups" lists.
    tibx = _chain()
    points = tibx.recovery_points()

    assert len(points) == 3
    assert [p.index for p in points] == [0, 1, 2]
    assert [p.slice_id for p in points] == SLICES


def test_recovery_point_carries_guid_and_times() -> None:
    point = _chain().recovery_points()[1]

    assert point.guid == uuid.UUID(bytes_le=bytes([3]) * 16)
    assert point.created.timestamp() == pytest.approx(3.0)
    assert point.finished.timestamp() == pytest.approx(3.01)


def test_latest_is_default() -> None:
    tibx = _chain()
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_select_by_index() -> None:
    tibx = _chain()
    tibx.use_recovery_point(0)
    assert tibx.streams()[0].read(0, 10) == b"base state"

    tibx.use_recovery_point(1)
    assert tibx.streams()[0].read(0, 18) == b"after first backup"

    tibx.use_recovery_point(2)
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_selection_is_by_slice_not_position() -> None:
    # Selecting a point takes every extent up to and including its slice id. Picking the
    # middle backup of a chain whose ids are 2, 3, 5 must not be read as "slice <= 1".
    tibx = _chain()
    tibx.use_recovery_point(1)

    assert {extent.slice_id for extent in tibx.extents} == {2, 3}


def test_select_oldest_and_latest() -> None:
    tibx = _chain()
    tibx.use_recovery_point("oldest")
    assert tibx.streams()[0].read(0, 10) == b"base state"
    tibx.use_recovery_point("latest")
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_index_out_of_range() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="out of range"):
        tibx.use_recovery_point(5)


def test_invalid_selector() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="invalid recovery point"):
        tibx.use_recovery_point("bogus")


def test_archive_without_slices_reports_no_recovery_points() -> None:
    # An archive whose slices tree is absent records no backups. Reporting none is right;
    # the previous behaviour counted commit roots and reported points that never existed.
    archive = build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)])
    tibx = TIBX(io.BytesIO(archive))

    assert tibx.recovery_points() == []
    with pytest.raises(InvalidArchiveError, match="records no backups"):
        tibx.use_recovery_point(0)


def test_recovery_points_from_memtree_and_ctrees() -> None:
    # As the slices tree grows its records move from the mem-tree into on-disk ctrees, like
    # those of every LSM tree. Across them the newest record of a slice wins.
    extents = [ExtentSpec(10, 0, b"x" * 64, slice_id=slice_id) for slice_id in SLICES]

    def cell(slice_id: int, marker: int) -> Cell:
        key = c_tibx.slice_key(slice_id=slice_id).dumps()
        return Cell(key, slice_record(bytes([marker]) * 16, 1000 * slice_id, 1000 * slice_id + 10))

    leaf_page = len(build_lsm_archive(extents)) // PAGE
    slices = lsb(
        4,
        len(c_tibx.slice_record),
        memtree_cells=[cell(3, 0x33)],  # newer than the ctree's record of slice 3
        ctrees=[(leaf_page * PAGE, 3)],
    )
    leaf = lsm_page(c_tibx.PageType.LEAF, b"LEAF", [cell(2, 2), cell(3, 3), cell(5, 5)], key_length=4, compact=True)
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, extra_slots={5: slices}) + leaf))

    points = tibx.recovery_points()
    assert [point.slice_id for point in points] == SLICES
    assert [point.guid.bytes_le[0] for point in points] == [2, 0x33, 5]

    tibx.use_recovery_point(2)
    assert tibx.extents


def test_recovery_points_are_the_backups_acronis_lists() -> None:
    # Acronis lists neither the deleted record nor the type 0xb one. Nor does it list a
    # backup that has not finished, but that one is listed here for its data to be selected.
    points = _with_records(RECORDS).recovery_points()

    assert [point.slice_id for point in points] == [2, 4, 6]
    assert [point.index for point in points] == [0, 1, 2]
    assert [point.type for point in points] == ["FULL", "DIFFERENTIAL", "FULL"]
    assert [point.finished is None for point in points] == [False, False, True]


def test_latest_is_the_newest_finished_backup() -> None:
    tibx = _with_records(RECORDS)
    assert tibx.streams()[0].read(0, 7) == b"slice 4"

    tibx.use_recovery_point(2)
    assert tibx.streams()[0].read(0, 7) == b"slice 6"

    tibx.use_recovery_point("latest")
    assert tibx.streams()[0].read(0, 7) == b"slice 4"


def test_latest_without_a_finished_backup() -> None:
    # Then "latest" leaves nothing out, not even data newer than every record
    tibx = _with_records([(2, FULL, 0, b"\x02" * 16)], slice_ids=[2, 3])
    assert tibx.streams()[0].read(0, 7) == b"slice 3"

    tibx.use_recovery_point(0)
    assert tibx.streams()[0].read(0, 7) == b"slice 2"


def test_latest_keeps_the_extents_when_none_is_newer() -> None:
    # Selecting the newest backup mostly leaves nothing out, and so copies no extents
    tibx = _chain()
    assert tibx.extents is tibx._unfiltered_extents()

    tibx.use_recovery_point(1)
    assert tibx.extents is not tibx._unfiltered_extents()


def test_select_by_guid() -> None:
    # A GUID names a backup for good, where an index shifts once older backups are deleted
    tibx = _chain()
    guid = tibx.recovery_points()[1].guid

    for selector in (guid, str(guid), str(guid).upper(), f"{{{guid}}}", guid.hex):
        tibx.use_recovery_point(selector)
        assert tibx.recovery_point.slice_id == 3
        assert {extent.slice_id for extent in tibx.extents} == {2, 3}


def test_unknown_guid() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="no recovery point with GUID"):
        tibx.use_recovery_point(uuid.UUID(int=0))


def test_malformed_guid() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="invalid recovery point"):
        tibx.use_recovery_point("not-a-guid-but-long-enough-to-look-like-one")


def test_selected_recovery_point() -> None:
    tibx = _chain()
    points = tibx.recovery_points()

    # "latest" reflects the newest backup that has finished
    assert tibx.recovery_point == points[-1]

    tibx.use_recovery_point(0)
    assert tibx.recovery_point == points[0]

    tibx.use_recovery_point("oldest")
    assert tibx.recovery_point == points[0]

    tibx.use_recovery_point("latest")
    assert tibx.recovery_point == points[-1]


def test_selected_recovery_point_with_one_not_finished() -> None:
    tibx = _with_records(RECORDS)
    points = tibx.recovery_points()
    assert tibx.recovery_point == points[1]

    tibx.use_recovery_point(2)
    assert tibx.recovery_point == points[2]


def test_selected_recovery_point_without_a_finished_backup() -> None:
    tibx = _with_records([(2, FULL, 0, b"\x02" * 16)])
    assert tibx.recovery_point is None


def test_selected_recovery_point_without_slices() -> None:
    tibx = TIBX(io.BytesIO(build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)])))
    assert tibx.recovery_point is None


def test_select_by_guid_of_a_replaced_backup() -> None:
    # The deleted record carries the GUID of the backup that replaced it; the GUID selects that one
    tibx = _with_records(RECORDS)
    tibx.use_recovery_point(uuid.UUID(bytes_le=RESTARTED))

    assert tibx.recovery_point.slice_id == 6
    assert tibx.streams()[0].read(0, 7) == b"slice 6"


def test_archive_uuid() -> None:
    # Stored mixed-endian, like the GUIDs of the archive's backups
    raw = bytes(range(16))
    tibx = TIBX(io.BytesIO(build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)], uuid=raw)))
    assert tibx.uuid == uuid.UUID(bytes_le=raw)


def test_recovery_point_statistics() -> None:
    record = c_tibx.slice_record(
        guid=b"\x01" * 16,
        user_size=0x10000,
        compr_size=0x4000,
        items_added=3,
        items_changed=2,
        items_removed=1,
        flags=c_tibx.SliceFlags(INCREMENTAL),
    )
    point = RecoveryPoint(0, 1, record)

    assert point.size == 0x10000
    assert point.compressed_size == 0x4000
    assert (point.items_added, point.items_changed, point.items_removed) == (3, 2, 1)
    assert point.type == "INCREMENTAL"


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (FULL, "FULL"),
        (INCREMENTAL, "INCREMENTAL"),
        (DIFFERENTIAL, "DIFFERENTIAL"),
        (HIDDEN, "DIFFERENTIAL"),
        (c_tibx.SliceFlags.DELETED | INCREMENTAL, "INCREMENTAL"),
    ],
)
def test_recovery_point_type(flags: int, expected: str) -> None:
    # The type of backup that was asked for, not the type its slice was written as
    record = c_tibx.slice_record(guid=b"\x01" * 16, flags=c_tibx.SliceFlags(flags))
    assert RecoveryPoint(0, 1, record).type == expected


@pytest.mark.parametrize(
    ("show_hidden", "show_deleted", "slice_ids"),
    [
        (False, False, [2, 4, 6]),
        (True, False, [2, 3, 4, 6]),
        (False, True, [2, 4, 5, 6]),
        (True, True, [2, 3, 4, 5, 6]),
    ],
)
def test_recovery_points_show_hidden_and_deleted(show_hidden: bool, show_deleted: bool, slice_ids: list[int]) -> None:
    # As libarchive3 can be asked to, list the slices Acronis hides and the deleted backups
    tibx = _with_records(RECORDS)
    points = tibx.recovery_points(show_hidden=show_hidden, show_deleted=show_deleted)

    assert [point.slice_id for point in points] == slice_ids
    assert [point.index for point in points] == list(range(len(slice_ids)))
    assert [point.hidden for point in points] == [slice_id == 3 for slice_id in slice_ids]
    assert [point.deleted for point in points] == [slice_id == 5 for slice_id in slice_ids]


def test_use_hidden_recovery_point() -> None:
    # A hidden slice is selected by its RecoveryPoint; indexes and "latest" keep to the
    # backups Acronis lists
    tibx = _with_records(RECORDS)
    hidden = next(point for point in tibx.recovery_points(show_hidden=True) if point.hidden)

    tibx.use_recovery_point(hidden)
    assert tibx.recovery_point == hidden
    assert tibx.streams()[0].read(0, 7) == b"slice 3"

    tibx.use_recovery_point(1)
    assert tibx.recovery_point.slice_id == 4

    tibx.use_recovery_point("latest")
    assert tibx.recovery_point.slice_id == 4


def test_recovery_point_equality() -> None:
    # The same backup is equal across lists, whatever its index; a deleted backup is not the
    # one that replaced it, though it carries its GUID
    tibx = _with_records(RECORDS)
    listed = tibx.recovery_points()
    everything = tibx.recovery_points(show_hidden=True, show_deleted=True)

    assert listed[1] == everything[2]
    assert (listed[1].index, everything[2].index) == (1, 2)
    assert set(listed) < set(everything)

    deleted, replacement = everything[3], everything[4]
    assert deleted.guid == replacement.guid
    assert deleted != replacement
    assert len({deleted, replacement}) == 2
