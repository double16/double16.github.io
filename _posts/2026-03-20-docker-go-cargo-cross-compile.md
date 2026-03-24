---
layout: post
title:  "Docker Multiple Platform Builds: Go and Cargo"
date:   2026-03-20
categories:
- docker
comments: true
---

Docker lets you build for multiple platforms (i.e. amd64 and arm64) in the same build process and publish a multi-platform build. Generally this requires an emulator in the docker process, like qemu, which isn't difficult to do. However, some things will not compile correctly and are better done with cross compiling. For example: Go and Rust.

Cross compiling works by configuring Docker for a build platform and target architecture. In the build commands, you give the compiler the target architecture.

For a full example, see my Kasm Workspace builds:
 - Dockerfile: [https://github.com/double16/pentest-tools/blob/master/attackhost/Dockerfile.kasm-kali](https://github.com/double16/pentest-tools/blob/master/attackhost/Dockerfile.kasm-kali)
 - Go build script: [https://github.com/double16/pentest-tools/blob/master/attackhost/provisioners/packages-go.sh](https://github.com/double16/pentest-tools/blob/master/attackhost/provisioners/packages-go.sh)
 - Rust (Cargo) script: [https://github.com/double16/pentest-tools/blob/master/attackhost/provisioners/packages-cargo.sh](https://github.com/double16/pentest-tools/blob/master/attackhost/provisioners/packages-cargo.sh)

## Go

```Dockerfile
FROM --platform=$BUILDPLATFORM golang:1.26 AS gobuild
ARG TARGETARCH
ARG BUILDPLATFORM
ENV DEBIAN_FRONTEND=noninteractive
ENV GOOS=linux GOARCH=$TARGETARCH
RUN apt-get update
ADD packages-go.sh /tmp
RUN --mount=type=cache,target=/usr/local/share/go-build-cache --mount=type=cache,target=/usr/local/share/go \
    /tmp/packages-go.sh
```

The `--platform` option to Docker tells it how to run the container, on your native architecture. The `ARG TARGETARCH` is how Docker tells you which architecture should be built. The values for each are a little different though:

`--platform`:
  - linux/amd64
  - linux/arm64

`TARGETARCH`:
  - amd64
  - arm64

The names make sense, one is a platform which includes the architecture, the other only the architecture. However, when writing your scripts is easy to get confused.

The build script gets messy if you want the build to work on either build platform. For example, if locally you use a Mac with Apple Silicon (arm64), but the build pipeline (GitHub) uses amd64.

If the package needs to compile C (or another language), you need to install the cross-compiler by name.

Go puts native executables in one place, cross-compiled executables elsewhere. It does makes sense if you're building both in the same filesystem. Docker is using different containers for each, so you need logic to figure that out. The script that copies files from `"${GOPATH}/bin/linux_${TARGETARCH}"` handles this. I like to add a test to make sure the binary landed where I expected it.

```shell
export GOPATH=/usr/local/share/go
export TARGET_DIR=/usr/local/bin
mkdir -p "${TARGET_DIR}"
if [ "$BUILDPLATFORM" == "linux/$TARGETARCH" ]; then
  export GOBIN="${TARGET_DIR}"
fi
export GOCACHE=/usr/local/share/go-build-cache
export GOFLAGS="-ldflags=-s -w"
export CGO_ENABLED=1

# setup for module that need to compile C code
CC=gcc CXX=g++
C_PACKAGES="build-essential pkg-config git ca-certificates"
if [ "$(arch)" = "arm64" ] || [ "$(arch)" = "aarch64" ]; then
  C_PACKAGES="${C_PACKAGES} gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross"
  if [ "$GOARCH" = "amd64" ]; then
    export CC=x86_64-linux-gnu-gcc CXX=x86_64-linux-gnu-g++
  fi
elif [ "$(arch)" = "amd64" ]; then
  C_PACKAGES="${C_PACKAGES} gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross"
  if [ "$GOARCH" = "arm64" ]; then
    export CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++
  fi
fi
apt-get install -y --no-install-recommends ${C_PACKAGES}

go install github.com/projectdiscovery/katana/cmd/katana@latest

if [ -d "${GOPATH}/bin/linux_${TARGETARCH}" ]; then
  find "${GOPATH}/bin/linux_${TARGETARCH}" -type f -print -exec cp {} "${TARGET_DIR}" \;
fi

test -x ${TARGET_DIR}/katana
```

## Rust

Rust has similar complications. It was enough I created a Docker image that has an `ONBUILD` handler to deal with it. See [https://github.com/double16/cargobuild](https://github.com/double16/cargobuild).

```Dockerfile
FROM --platform=$BUILDPLATFORM ghcr.io/double16/cargobuild:latest AS cargobuild
ADD packages-cargo.sh /tmp
RUN --mount=type=cache,target=/usr/local/share/cargo \
    /tmp/packages-cargo.sh
```

```shell
# Get target specific vars, from the cargobuild image
if [[ -f "/etc/environment" ]]; then
  . /etc/environment
fi
# Setup the cargo environment, from the cargobuild image
if [[ -f "${HOME}/.cargo/env" ]]; then
  . "${HOME}/.cargo/env"
else
  export CARGO_HOME=/usr/local/share/cargo
fi
for CARGO in rustscan feroxbuster; do
  cargo install --root /usr/local ${TARGET:+--target ${TARGET}} "${CARGO}"
done
```

## Moving Targets

As versions of Go and Rust are released, sometimes how cross compiling is handled breaks. I use my `pentest-tools` repo regularly. Check the files I referenced at the beginning for the latest working script-fu.
