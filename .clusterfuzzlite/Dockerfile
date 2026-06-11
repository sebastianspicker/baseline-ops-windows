FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04

ENV SRC=/src
ENV OUT=/out

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs=18.19.1+dfsg-6ubuntu5 \
        npm=9.2.0~ds1-2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$SRC" "$OUT"

COPY . "$SRC/win-mdm-security-hardening-kit"
WORKDIR "$SRC/win-mdm-security-hardening-kit"

COPY .clusterfuzzlite/build.sh "$SRC/build.sh"
