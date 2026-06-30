#checkov:skip=CKV_DOCKER_2: ClusterFuzzLite build image exits after producing fuzz targets; no service healthcheck applies.
FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81

ENV SRC=/src
ENV OUT=/out

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs=18.19.1+dfsg-6ubuntu5 \
        npm=9.2.0~ds1-2 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p "$SRC" "$OUT" \
 && useradd --create-home --shell /usr/sbin/nologin fuzz \
 && chown -R fuzz:fuzz "$SRC" "$OUT"

COPY --chown=fuzz:fuzz . "$SRC/win-mdm-security-hardening-kit"
WORKDIR "$SRC/win-mdm-security-hardening-kit"

COPY --chown=fuzz:fuzz .clusterfuzzlite/build.sh "$SRC/build.sh"
USER fuzz
