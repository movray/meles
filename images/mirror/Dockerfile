# The cvdupdate container of the meles database mirror: cvdupdate by Cisco
# Talos (Apache-2.0) and its dependencies, unchanged, on Chainguard's Python
# image (no shell, no pip). The licenses of all packages stay in their
# *.dist-info directories. Built and published by the release workflow as
# ghcr.io/movray/meles-mirror; the signature databases are never part of it.
#
# The wheels are pure Python: they are installed once on the build platform
# and copied into the image of every target platform, without emulation.
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/python:latest-dev@sha256:88d8715285b78746679a86fa126fe01e68b7940c3299ee3b4cf8245d4b17095f AS build
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-compile --require-hashes --no-deps --only-binary :all: \
      --target /tmp/app/lib -r /tmp/requirements.txt \
 && rm -rf /tmp/app/lib/bin

FROM cgr.dev/chainguard/python:latest@sha256:d914788ef74519450a69bc5cce6a1cc747dbefb95a3d431daa4ff707767fea8a
COPY --from=build /tmp/app/lib /app/lib
COPY update.py /app/update.py
ENV PYTHONPATH=/app/lib PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
LABEL org.opencontainers.image.source="https://github.com/movray/meles" \
      org.opencontainers.image.description="cvdupdate (by Cisco Talos) for the meles ClamAV database mirror"
ENTRYPOINT ["python", "/app/update.py"]
