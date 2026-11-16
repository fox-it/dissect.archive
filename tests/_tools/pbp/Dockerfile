# Toolchain image for generating the "hello world" PBP test fixture, see generate.sh.
#
# The image combines the PlayStation Portable toolchain (pspdev) with sign_np, the tool
# that turns a PSP UMD image into a signed PSN EBOOT.PBP with a NPUMDIMG (DATA.PSAR) image.
ARG PSPDEV_IMAGE=pspdev/pspdev:v20261001
FROM ${PSPDEV_IMAGE}

ARG SIGN_NP_REPOSITORY=https://github.com/swarzesherz/sign_np.git
ARG SIGN_NP_COMMIT=ac77d56e13b5c6c60564100699560d12ff3f425f

RUN apk add --no-cache bash build-base cdrkit coreutils git gzip imagemagick libfaketime zlib-dev

# sign_np was written for older compilers and Windows: it uses the *64 large file aliases
# that musl no longer provides, and relies on implicit declarations that newer GCC rejects.
#
# It also has two buffer overflows, which the stack protector and _FORTIFY_SOURCE of the
# toolchain image turn into crashes. Both are fixed without changing the output:
# - PSP_SYSTEM_VER ("6.20" plus its terminator, 5 bytes) is read into a 4 byte buffer
# - The ECDSA signature halves (20 bytes each) are copied out as 0x20 bytes each
RUN git clone --quiet "${SIGN_NP_REPOSITORY}" /tmp/sign_np \
    && git -C /tmp/sign_np checkout --quiet "${SIGN_NP_COMMIT}" \
    && sed -i \
        -e 's/u8 sys_ver\[0x4\];/u8 sys_ver[0x10];/' \
        -e 's/memset(sys_ver, 0, 0x4);/memset(sys_ver, 0, 0x10);/' \
        /tmp/sign_np/sign_np.c \
    && sed -i \
        -e 's/memcpy(outR,R+1,0x20);/memcpy(outR,R+1,20);/' \
        -e 's/memcpy(outS,S+1,0x20);/memcpy(outS,S+1,20);/' \
        /tmp/sign_np/libkirk/ec.c \
    && grep -q 'u8 sys_ver\[0x10\];' /tmp/sign_np/sign_np.c \
    && grep -q 'memset(sys_ver, 0, 0x10);' /tmp/sign_np/sign_np.c \
    && grep -q 'memcpy(outR,R+1,20);' /tmp/sign_np/libkirk/ec.c \
    && grep -q 'memcpy(outS,S+1,20);' /tmp/sign_np/libkirk/ec.c \
    && make -C /tmp/sign_np \
        CFLAGS="-O2 -std=gnu17 -fpermissive -w -I./libkirk -Dfseeko64=fseeko -Dftello64=ftello" \
    && install -m 0755 /tmp/sign_np/sign_np /usr/local/bin/sign_np \
    && rm -rf /tmp/sign_np
