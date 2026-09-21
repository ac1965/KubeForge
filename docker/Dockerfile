# syntax=docker/dockerfile:1
#
# 公式の archlinux イメージは amd64 のみ提供されているため、Apple Silicon
# (arm64) ホストでも --platform=linux/amd64 を固定して QEMU エミュレーション
# でビルドする。
FROM --platform=linux/amd64 archlinux:latest

ARG TRIVY_VERSION=0.74.0
ARG KUBE_BENCH_VERSION=0.16.0

# --disable-sandbox: pacman 6.1+ のダウンロード用 seccomp サンドボックスは
# QEMU (linux/amd64 on Apple Silicon) 上のエミュレーションでは動作しないため無効化する。
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
    curl -sSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz

# kube-bench (CIS Kubernetes Benchmark auditor)
RUN set -eux; \
    curl -sSL -o /tmp/kube-bench.tar.gz \
      "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_amd64.tar.gz"; \
    tar -xzf /tmp/kube-bench.tar.gz -C /usr/local/bin kube-bench; \
    rm /tmp/kube-bench.tar.gz

RUN useradd -m -s /bin/bash forger
WORKDIR /workspace
COPY scripts/ /workspace/scripts/
RUN chown -R forger:forger /workspace

USER forger
ENTRYPOINT ["/bin/bash"]
