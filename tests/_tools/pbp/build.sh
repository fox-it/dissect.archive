#!/usr/bin/env bash
#
# Build the "hello world" PBP test fixture. This runs inside the toolchain image, use
# generate.sh to run it.
#
# Usage: build.sh <source directory> <output directory>
set -euo pipefail

readonly SRC_DIR="${1:?Missing source directory}"
readonly OUT_DIR="${2:?Missing output directory}"

# The content ID of the PSN release, which also determines the DISC_ID (NPUZ00001)
readonly CONTENT_ID="UP0000-NPUZ00001_00-DISSECTHELLO0001"
readonly UMD_ID="NPUZ-00001"
readonly DISC_ID="NPUZ00001"
readonly TITLE="Hello Dissect"

# The tools run with a frozen clock, which makes the UMD image reproducible. The NPUMDIMG
# header key and signatures are not: besides the time, sign_np seeds its random number
# generator with uninitialized stack memory
export TZ=UTC
readonly TIMESTAMP="2024-01-01 00:00:00"

log() { printf '[INFO] %s\n' "$*" >&2; }
error() { printf '[ERROR] %s\n' "$*" >&2; }

frozen() { faketime "${TIMESTAMP}" "$@"; }

# sign_np reports errors on stdout and exits with 0 regardless, so its output is checked too.
# Its output is unbuffered so that it is complete even if sign_np crashes.
run_sign_np() {
    local output status=0
    output="$(frozen stdbuf -o0 sign_np "$@")" || status=$?
    printf '%s\n' "${output}" >&2
    if [[ "${status}" -ne 0 ]] || grep -q "ERROR" <<< "${output}"; then
        error "sign_np failed (exit status ${status})"
        exit 1
    fi
}

for tool in psp-config mksfoex magick genisoimage sign_np faketime; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        error "Missing required tool: ${tool}"
        exit 1
    fi
done

WORK_DIR="$(mktemp -d)"
readonly WORK_DIR
trap 'rm -rf "${WORK_DIR}"' EXIT

log "Compiling the hello world executable"
cp -r "${SRC_DIR}/hello" "${WORK_DIR}/hello"
make -C "${WORK_DIR}/hello" clean all

log "Mastering the UMD image"
readonly UMD="${WORK_DIR}/umd"
mkdir -p "${UMD}/PSP_GAME/SYSDIR"

printf '%s|%s|0001|G' "${UMD_ID}" "0000000000000001" > "${UMD}/UMD_DATA.BIN"
mksfoex \
    -s CATEGORY=UG \
    -s DISC_ID="${DISC_ID}" \
    -s DISC_VERSION=1.00 \
    -s PSP_SYSTEM_VER=6.20 \
    -d DISC_NUMBER=1 \
    -d DISC_TOTAL=1 \
    "${TITLE}" "${UMD}/PSP_GAME/PARAM.SFO"

# The icon and the background, at the sizes the XMB shows them at
magick -size 144x80 "gradient:#1c4c8c-#0b1a33" -depth 8 -strip "${UMD}/PSP_GAME/ICON0.PNG"
magick -size 480x272 "gradient:#203060-#101030" -depth 8 -strip "${UMD}/PSP_GAME/PIC1.PNG"

# The executable on a UMD is a signed (and encrypted) ~PSP module
run_sign_np -elf "${WORK_DIR}/hello/hello.prx" "${UMD}/PSP_GAME/SYSDIR/EBOOT.BIN" 0

find "${UMD}" -exec touch -h -d "${TIMESTAMP}" {} +
# The ISO reader of sign_np only accepts directory records that have a system use field, so
# the image gets (rationalized) CD-XA attributes
frozen genisoimage -quiet \
    -xa \
    -sysid "PSP GAME" \
    -appid "PSP GAME" \
    -volid "${DISC_ID}" \
    -volset "${DISC_ID}" \
    -publisher "DISSECT" \
    -preparer "DISSECT" \
    -output "${WORK_DIR}/hello.iso" \
    "${UMD}"

log "Converting the UMD image to a PSN EBOOT.PBP"
# Compressed with LZRC, and encrypted with the NPDRM fixed key (a version key of 0)
run_sign_np -pbp -c "${WORK_DIR}/hello.iso" "${WORK_DIR}/EBOOT.PBP" "${CONTENT_ID}" 0

if [[ "$(head -c 4 "${WORK_DIR}/EBOOT.PBP" | od -An -tx1 | tr -d ' ')" != "00504250" ]]; then
    error "sign_np did not produce a PBP"
    exit 1
fi

gzip -9 --no-name < "${WORK_DIR}/EBOOT.PBP" > "${OUT_DIR}/hello.pbp.gz"

log "Generated ${OUT_DIR}/hello.pbp.gz"
log "UMD image: $(stat -c %s "${WORK_DIR}/hello.iso") bytes, sha256 $(sha256sum "${WORK_DIR}/hello.iso" | cut -d' ' -f1)"
log "EBOOT.PBP: $(stat -c %s "${WORK_DIR}/EBOOT.PBP") bytes, sha256 $(sha256sum "${WORK_DIR}/EBOOT.PBP" | cut -d' ' -f1)"
