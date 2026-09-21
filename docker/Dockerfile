# syntax=docker/dockerfile:1
#
# 公式の archlinux イメージ (docker.io/library/archlinux) は amd64 のみ
# 提供されている。Arch Linux 自体が x86_64 向けディストリビューションであり、
# ARM 対応は姉妹プロジェクトの Arch Linux ARM (archlinuxarm.org) が別途
# 提供しているため、arm64 (Apple Silicon 等) ではそちらの rootfs を使って
# ネイティブにビルドする。amd64 では QEMU エミュレーション不要でそのまま、
# arm64 では ALARM rootfs を使うことで、どちらもエミュレーションなしで
# ビルドできる。
ARG TARGETARCH

FROM archlinux:latest AS base-amd64

# ALARM の rootfs tarball を取得して展開するだけの中間ステージ。
# curl/tar を含む多アーキテクチャ対応イメージ (alpine) 上で行う。
FROM alpine:3.20 AS alarm-fetch
RUN apk add --no-cache curl
RUN set -eux; \
    mkdir -p /alarm-rootfs; \
    curl -sSL http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz -o /tmp/alarm.tar.gz; \
    tar -xzpf /tmp/alarm.tar.gz -C /alarm-rootfs --numeric-owner; \
    rm /tmp/alarm.tar.gz

FROM scratch AS base-arm64
COPY --from=alarm-fetch /alarm-rootfs/ /

FROM base-${TARGETARCH} AS base

ARG TARGETARCH
ARG TRIVY_VERSION=0.74.0
ARG KUBE_BENCH_VERSION=0.16.0

# ALARM は独自のパッケージ署名鍵を使うため、arm64 の場合のみ鍵を初期化する
# (amd64 の archlinux イメージは pacman-key が初期化済みのため no-op)。
RUN set -eux; \
    if [ "${TARGETARCH}" = "arm64" ]; then \
      pacman-key --init; \
      pacman-key --populate archlinuxarm; \
    fi

# --disable-sandbox: pacman 6.1+ のダウンロード用 seccomp サンドボックスは
# 一部のコンテナビルド環境 (QEMU エミュレーション下など) で動作しないため
# 明示的に無効化する。
RUN pacman -Syu --noconfirm --disable-sandbox --needed \
      base-devel \
      git \
      curl \
      wget \
      tar \
      jq \
      nmap \
      python \
      go \
      kubectl \
      ca-certificates \
      && pacman -Scc --noconfirm \
      && rm -rf /var/cache/pacman/pkg/*

# Trivy (image / filesystem vulnerability scanner) — installed from upstream
# release tarballs because it is not in the official Arch repos.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH=64bit ;; \
      arm64) TRIVY_ARCH=ARM64 ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -sSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz

# kube-bench (CIS Kubernetes Benchmark auditor)
RUN set -eux; \
    curl -sSL -o /tmp/kube-bench.tar.gz \
      "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    tar -xzf /tmp/kube-bench.tar.gz -C /usr/local/bin kube-bench; \
    rm /tmp/kube-bench.tar.gz

RUN useradd -m -s /bin/bash forger
WORKDIR /workspace
COPY scripts/ /workspace/scripts/
COPY manifests/audits/ /workspace/manifests/audits/
RUN chown -R forger:forger /workspace

USER forger
ENTRYPOINT ["/bin/bash"]
