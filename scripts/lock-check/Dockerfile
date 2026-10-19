# Image for the live lock checks (scripts/live-check-locked.sh): Ubuntu,
# Node 22 LTS and the three agent CLIs, nothing else. No repo files and no
# secrets: it is built with no build context, from this file on stdin
#   docker build -t saiife-lockcheck:local - < scripts/lock-check/Dockerfile
# so COPY/ADD cannot work and are not used. The check scripts are mounted
# read-only at run time; logins live in the saiife-lockcheck-home volume.
#
# Versions: NODE_VERSION is pinned and checked against nodejs.org's
# SHASUMS256.txt. The agent versions default to `latest` on purpose (the
# checks record what was installed in each result header); pin one with
# CLAUDE_VERSION=... CODEX_VERSION=... GEMINI_VERSION=... in the host
# environment, which the wrapper passes as --build-arg (use --rebuild).
FROM ubuntu:24.04

ARG NODE_VERSION=22.14.0
ARG CLAUDE_VERSION=latest
ARG CODEX_VERSION=latest
ARG GEMINI_VERSION=latest
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils jq git util-linux procps coreutils \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=x64 ;; \
      arm64) arch=arm64 ;; \
      *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    tarball="node-v${NODE_VERSION}-linux-${arch}.tar.xz"; \
    cd /tmp; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${tarball}"; \
    curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"; \
    grep " ${tarball}\$" SHASUMS256.txt | sha256sum -c -; \
    tar -xJf "${tarball}" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "${tarball}" SHASUMS256.txt; \
    node --version; npm --version

RUN npm install -g \
      "@anthropic-ai/claude-code@${CLAUDE_VERSION}" \
      "@openai/codex@${CODEX_VERSION}" \
      "@google/gemini-cli@${GEMINI_VERSION}" \
 && npm cache clean --force

RUN useradd -m -u 1001 agent
