# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

#
# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
#

FROM docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS default
ARG TARGETARCH
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -yq --no-install-recommends ca-certificates tzdata && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r -g 2000 stalwart && \
    useradd -r -u 2000 -g 2000 -s /usr/sbin/nologin -M stalwart && \
    mkdir -p /etc/stalwart /var/lib/stalwart /etc/stalwart-v1 /var/lib/stalwart-v1 /var/lib/stalwart-migrate && \
    chown stalwart:stalwart /etc/stalwart /var/lib/stalwart /etc/stalwart-v1 /var/lib/stalwart-v1 /var/lib/stalwart-migrate
COPY --chmod=0755 bin/${TARGETARCH}/stalwart-migrate /usr/local/bin/stalwart-migrate
USER stalwart
WORKDIR /var/lib/stalwart-migrate
VOLUME ["/etc/stalwart", "/var/lib/stalwart", "/etc/stalwart-v1", "/var/lib/stalwart-v1", "/var/lib/stalwart-migrate"]
ENTRYPOINT ["/usr/local/bin/stalwart-migrate"]

FROM default AS fdb
ARG TARGETARCH
COPY --chmod=0644 bin/${TARGETARCH}/libfdb_c.so /usr/lib/libfdb_c.so
