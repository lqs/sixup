#!/bin/sh
# Cross-compile static binaries for the common platforms into dist/, with checksums.
# Usage: ./build.sh [version]           version defaults to git describe of the last v* tag
#        TARGETS="linux/amd64 linux/arm64" ./build.sh   build only these platforms
#        SLIM=0 ./build.sh              keep the stdlib and dependency code the tools/slim
#                                       stubs drop by default; see tools/slim/overlay.sh
#        PACKAGES="deb apk" ./build.sh  build only these Linux packages, PACKAGES= builds none
# Artifacts: dist/sixup-<version>-<os>-<uname -m>, the Linux ones also packaged as
# dist/sixup-<version>-<format>-<distribution arch>.<ext> (see packaging/nfpm.yaml),
# plus dist/SHA256SUMS.
set -eu

cd "$(dirname "$0")"
VERSION="${1:-$(git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo dev)}"
OUT=dist
LDFLAGS="-s -w -X main.version=${VERSION}"

# os/arch[/variant]; variant is GOARM for arm and GOMIPS for mips.
# Non-Linux binaries only support -dry-run: the protocol side is complete, the
# kernel configuration side is a stub. Useful for inspecting line parameters from a
# laptop plugged straight into the ONU. Windows is excluded because x/net/ipv6 has no
# control messages there, so the RA hop limit cannot be read.
DEFAULT_TARGETS="
linux/amd64
linux/arm64
linux/arm/7
linux/arm/6
linux/mipsle/softfloat
linux/mips/softfloat
linux/riscv64
darwin/arm64
darwin/amd64
freebsd/amd64
"
TARGETS="${TARGETS:-$DEFAULT_TARGETS}"
PACKAGES="${PACKAGES-deb rpm apk archlinux}"
NFPM_VERSION=v2.47.0

mkdir -p "$OUT"
rm -f "$OUT"/SHA256SUMS

SLIM_DIR="" NFPM_DIR=""
trap 'rm -rf "$SLIM_DIR" "$NFPM_DIR"' EXIT

SLIM_FLAGS=""
if [ "${SLIM:-1}" = "1" ]; then
	SLIM_DIR=$(tools/slim/overlay.sh)
	SLIM_FLAGS="-modfile $SLIM_DIR/go.mod -overlay $SLIM_DIR/overlay.json"
fi

if [ -n "$PACKAGES" ]; then
	NFPM_DIR=$(mktemp -d)
	GOBIN="$NFPM_DIR" go install "github.com/goreleaser/nfpm/v2/cmd/nfpm@$NFPM_VERSION"
	# dpkg, rpm and apk each accept only a few version shapes, and dotted numbers are
	# the one they share. A build on a tag takes the tag; any other build appends the
	# commit time to the last tag, so packages still sort in build order.
	PKG_VERSION=${VERSION#v}
	if ! echo "$PKG_VERSION" | grep -Eq '^[0-9]+(\.[0-9]+)*$'; then
		base=$(git describe --tags --match 'v*' --abbrev=0 2>/dev/null || echo 0)
		PKG_VERSION=${base#v}.$(git log -1 --format=%cd --date=format:%Y%m%d%H%M%S)
	fi
fi

# The architecture name each distribution uses for a build target, empty where the
# distribution has no such port. 32-bit arm: Debian armhf also covers the ARMv6 Raspberry
# Pi OS, so it gets the ARMv6 build, while Alpine and Arch Linux ARM have a port for each.
# MIPS routers run OpenWrt, whose packages these are not.
dist_arch() {
	case "$1:$2" in
		*:amd64) [ "$1" = deb ] && echo amd64 || echo x86_64 ;;
		*:arm64) [ "$1" = deb ] && echo arm64 || echo aarch64 ;;
		*:riscv64) echo riscv64 ;;
		deb:arm-6 | apk:arm-6) echo armhf ;;
		apk:arm-7) echo armv7 ;;
		rpm:arm-7) echo armv7hl ;;
		archlinux:arm-7) echo armv7h ;;
		archlinux:arm-6) echo armv6h ;;
	esac
}

# The name `uname -m` prints on the machine a build target runs on, so the binary to
# download is the one matching that output. The exception is little-endian MIPS, which
# prints mips like its big-endian sibling and is told apart by the Debian name mipsel.
machine() {
	case "$1:$2" in
		linux:amd64 | darwin:amd64) echo x86_64 ;;
		linux:arm64) echo aarch64 ;;
		linux:arm-7) echo armv7l ;;
		linux:arm-6) echo armv6l ;;
		linux:mipsle-*) echo mipsel ;;
		linux:mips-*) echo mips ;;
		*) echo "$2" ;;
	esac
}

for t in $TARGETS; do
	os=${t%%/*}; rest=${t#*/}
	arch=${rest%%/*}
	variant=""
	case "$rest" in */*) variant=${rest#*/} ;; esac

	env_extra=""
	case "$arch" in
		arm)  variant=${variant:-7}; env_extra="GOARM=$variant" ;;
		mips|mipsle) variant=${variant:-softfloat}; env_extra="GOMIPS=$variant" ;;
	esac
	target="$arch${variant:+-$variant}"
	name="sixup-${VERSION}-${os}-$(machine "$os" "$target")"

	printf '%-40s' "$name"
	# shellcheck disable=SC2086
	env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" $env_extra \
		go build -trimpath $SLIM_FLAGS -ldflags="$LDFLAGS" -o "$OUT/$name" .
	size=$(wc -c < "$OUT/$name" | tr -d ' ')
	printf '%8d bytes\n' "$size"

	[ "$os" = linux ] || continue
	# nfpm reads contents from fixed paths only, so the binary goes where nfpm.yaml expects it.
	cp "$OUT/$name" "$OUT/sixup"
	for p in $PACKAGES; do
		distarch=$(dist_arch "$p" "$target")
		[ -n "$distarch" ] || continue
		# The format leads the name, so a sorted listing groups each distribution's packages.
		label=$p ext=$p
		[ "$p" = archlinux ] && label=arch ext=pkg.tar.zst
		ARCH="$distarch" PKG_VERSION="$PKG_VERSION" "$NFPM_DIR/nfpm" package -f packaging/nfpm.yaml -p "$p" \
			-t "$OUT/sixup-$VERSION-$label-$distarch.$ext"
	done
	rm "$OUT/sixup"
done

# The licence of sixup and the notice of the work it derives from travel with the binaries:
# a release is a distribution, and both licences ask for their text to come along.
cp LICENSE NOTICE "$OUT/"

(cd "$OUT" && sha256sum sixup-"${VERSION}"-* > SHA256SUMS 2>/dev/null || shasum -a 256 sixup-"${VERSION}"-* > SHA256SUMS)
echo "written to $OUT/, checksums in $OUT/SHA256SUMS"
