# syntax=docker/dockerfile:1.7
# Builds the pinned, non-service image used to compile and run the JavaScript
# profile-validation fuzz target with the same PowerShell runtime as release CI.
#checkov:skip=CKV_DOCKER_2: ClusterFuzzLite build image exits after producing fuzz targets; no service healthcheck applies.
#checkov:skip=CKV_DOCKER_4: Remote ADD is required here and is locked to the official archive SHA-256.
FROM mcr.microsoft.com/dotnet/runtime:10.0-noble-amd64@sha256:567d204c2121716af76125c401f0684cfe06f8c6ba9a6783374464f625b79acb

ENV POWERSHELL_VERSION=7.6.3 \
    SRC=/src \
    OUT=/out \
    PATH="/opt/microsoft/powershell/7:${PATH}"

ADD --checksum=sha256:856d0765d2332377f9d7a4aea76efdfde4de51446e7738dde2dfda41dba9e2a7 \
    https://github.com/PowerShell/PowerShell/releases/download/v7.6.3/powershell-7.6.3-linux-x64.tar.gz \
    /tmp/powershell.tar.gz

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs=18.19.1+dfsg-6ubuntu5 \
        npm=9.2.0~ds1-2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/microsoft/powershell/7 "$SRC" "$OUT" \
    && tar -xzf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7 \
    && rm -f /tmp/powershell.tar.gz \
    && chmod 0755 /opt/microsoft/powershell/7/pwsh \
    && test "$(pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')" = "$POWERSHELL_VERSION" \
    && useradd --create-home --shell /usr/sbin/nologin fuzz \
    && chown -R fuzz:fuzz "$SRC" "$OUT"

COPY --chown=fuzz:fuzz . "$SRC/baselineops-windows"
WORKDIR "$SRC/baselineops-windows"

COPY --chown=fuzz:fuzz --chmod=0755 .clusterfuzzlite/build.sh "$SRC/build.sh"
USER fuzz
HEALTHCHECK NONE
