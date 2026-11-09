from __future__ import annotations

from dissect.cstruct import cstruct

pbp_def = """
struct PBPHeader {
    char        magic[4];                       /* 0x0000 */
    uint32      version;                        /* 0x0004 */
    uint32      offsets[8];                     /* 0x0008: offset of each subfile, which ends at the next one */
};
"""

c_pbp = cstruct(endian="<").load(pbp_def)
