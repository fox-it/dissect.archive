#!/usr/bin/env bash
#
# Generate the "hello world" PBP test fixture (tests/_data/hello.pbp.gz), a signed PSN
# EBOOT.PBP that contains a NPUMDIMG (DATA.PSAR) image of a small PSP UMD image.
#
# The fixture is built with real tools in a Docker image (see Dockerfile and build.sh):
# the executable is compiled with the PlayStation Portable SDK, the UMD image is mastered
# with genisoimage, and the PBP and its NPUMDIMG image are written by sign_np.
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DATA_DIR="$(cd "${SCRIPT_DIR}/../../_data" && pwd)"
readonly IMAGE="dissect-archive-pbp-fixture"

log() { printf '[INFO] %s\n' "$*" >&2; }

log "Building the toolchain image"
docker build --tag "${IMAGE}" - < "${SCRIPT_DIR}/Dockerfile"

log "Building the fixture"
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --volume "${SCRIPT_DIR}:/src:ro" \
    --volume "${DATA_DIR}:/out" \
    "${IMAGE}" \
    bash /src/build.sh /src /out

log "All done"
