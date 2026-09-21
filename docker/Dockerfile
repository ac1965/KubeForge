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

# libcap (base-devel の依存) が同梱する captree は本イメージでは未使用の
# Go 製ツールで、libcap パッケージのリリース当時の古い Go stdlib が
# 埋め込まれたままになっており Trivy スキャンで HIGH 脆弱性として検出される。
# 使わないバイナリなので削除する。
RUN rm -f /usr/bin/captree

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

# kube-bench (CIS Kubernetes Benchmark auditor) — ソースからビルドする。
# 公式のビルド済みバイナリ (GitHub Releases / Docker Hub イメージ) は
# リリース時点の Go バージョンのまま固定されており、Trivy でスキャンすると
# 埋め込まれた Go 標準ライブラリ由来の HIGH 脆弱性が複数検出される
# (コンテナ OS 側をいくら新しくしても、コンパイル済みバイナリの中身は
# 変わらないため解消しない)。Arch Linux の最新 go でビルドし直すことで
# この問題を解消する。cfg/ (CIS ベンチマーク定義) はビルド済みバイナリには
# 含まれないため、ソース tarball から別途取り出して同梱する。
RUN set -eux; \
    curl -sSL -o /tmp/kube-bench-src.tar.gz \
      "https://github.com/aquasecurity/kube-bench/archive/refs/tags/v${KUBE_BENCH_VERSION}.tar.gz"; \
    mkdir -p /tmp/kube-bench-src; \
    tar -xzf /tmp/kube-bench-src.tar.gz -C /tmp/kube-bench-src --strip-components=1; \
    cd /tmp/kube-bench-src; \
    CGO_ENABLED=0 go build \
      -ldflags "-X github.com/aquasecurity/kube-bench/cmd.KubeBenchVersion=${KUBE_BENCH_VERSION}" \
      -o /usr/local/bin/kube-bench .; \
    mkdir -p /opt/kube-bench; \
    cp -r cfg /opt/kube-bench/cfg; \
    cd /; \
    rm -rf /tmp/kube-bench-src /tmp/kube-bench-src.tar.gz "$(go env GOCACHE)" "$(go env GOMODCACHE)"

RUN useradd -m -s /bin/bash forger
WORKDIR /workspace
COPY scripts/ /workspace/scripts/
COPY manifests/audits/ /workspace/manifests/audits/
RUN chown -R forger:forger /workspace

USER forger
ENTRYPOINT ["/bin/bash"]
