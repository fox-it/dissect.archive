from __future__ import annotations

from dissect.cstruct import cstruct

psar_def = """
flag BlockFlags : uint32 {
    NO_MAC      = 0x1,                          /* The block has no MAC to verify */
    UNENCRYPTED = 0x4,
};

struct Header {
    char        magic[8];                       /* 0x0000: NPUMDIMG */
    uint32      np_flags;                       /* 0x0008: 0x01000003 if the version key is the fixed key, else 0x2 */
    uint32      block_lbas;                     /* 0x000c */
    char        content_id[0x24];               /* 0x0010: e.g. UP0000-NPUZ00001_00-0000000000000000 */
    char        _reserved_34[0x0c];             /* 0x0034 */
    char        body[0x60];                     /* 0x0040: HeaderBody, encrypted with the header key */
    char        header_key[0x10];               /* 0x00a0 */
    char        table_mac[0x10];                /* 0x00b0: BBMac of the block table */
    char        header_mac[0x10];               /* 0x00c0: BBMac of 0x0000-0x00c0 */
    char        padding[0x08];                  /* 0x00d0: random */
    char        signature[0x28];                /* 0x00d8: ECDSA signature of 0x0000-0x00d8 */
};

/* The decrypted body of the header, the offsets are relative to the start of the header */
struct HeaderBody {
    uint16      sector_size;                    /* 0x0040: 0x800 */
    uint16      unk_42;                         /* 0x0042: 0xe001 if the image is larger than 1 GiB, else 0xe000 */
    char        unk_44[0x10];                   /* 0x0044 */
    uint32      lba_start;                      /* 0x0054 */
    uint32      unk_58;                         /* 0x0058 */
    uint32      unk_5c;                         /* 0x005c: lba_end, but at most 0x6c0bf */
    uint32      unk_60;                         /* 0x0060 */
    uint32      lba_end;                        /* 0x0064 */
    uint32      unk_68;                         /* 0x0068 */
    uint32      table_offset;                   /* 0x006c */
    char        disc_id[0x10];                  /* 0x0070: e.g. NPUZ-00001 */
    char        unk_80[0x20];                   /* 0x0080 */
};

struct Block {
    char        mac[0x10];                      /* 0x0000: BBMac of the stored data, also scrambles the entry */
    uint32      offset;                         /* 0x0010 */
    uint32      size;                           /* 0x0014: smaller than a block if the data is compressed */
    BlockFlags  flags;                          /* 0x0018 */
    uint32      unk_1c;                         /* 0x001c: non-zero if the block is not stored */
};
"""

c_psar = cstruct(endian="<").load(psar_def)
