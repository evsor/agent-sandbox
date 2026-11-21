# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM scratch AS tools
ADD --chown=0:0 --checksum=sha256:77b9e297e94c50336823d0f84de7ef1be60cba704601fa0d98f129f47a94987b --unpack=true \
    https://github.com/cli/cli/releases/download/v2.102.1/gh_2.102.1_linux_amd64.tar.gz /

FROM node:26-trixie-slim@sha256:80eccfd7e3fa8663c84881efb6b28c7411672a337aec1769f0fb9e3adc4a4d8b

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash-completion \
        ca-certificates \
        curl \
        git \
        jq \
        less \
        make \
        procps \
        python3 \
        python3-venv \
        ripgrep \
        unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.4@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b /uv /uvx /usr/local/bin/
COPY --from=tools /gh_*/bin/gh /usr/local/bin/
RUN gh completion -s bash > /usr/share/bash-completion/completions/gh

ARG CLAUDE_CODE_VERSION=2.1.304
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && npm cache clean --force

COPY image/etc/claude-code/ /etc/claude-code/
COPY image/etc/gitconfig image/etc/gitignore /etc/
RUN chmod -R a+rX,go-w /etc/claude-code /etc/gitconfig /etc/gitignore

# Volume mount points
RUN mkdir -p /workspace /home/node/claude-state \
    && chown node:node /workspace /home/node/claude-state

ENV CLAUDE_CONFIG_DIR=/home/node/claude-state \
    USER=node \
    LOGNAME=node \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/node/.local/bin

USER node
WORKDIR /workspace
CMD ["bash"]
