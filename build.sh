#!/bin/sh
# Cross-compile static binaries for the common platforms into dist/, with checksums.
# Usage: ./build.sh [version]           version defaults to git describe
#        TARGETS="linux/amd64 linux/arm64" ./build.sh   build only these platforms
#        SLIM=0 ./build.sh              keep the stdlib and dependency code the tools/slim
#                                       stubs drop by default; see tools/slim/overlay.sh
# Artifacts: dist/sixup-<version>-<os>-<arch>[-<variant>], plus dist/SHA256SUMS.
set -eu

cd "$(dirname "$0")"
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
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

mkdir -p "$OUT"
rm -f "$OUT"/SHA256SUMS

SLIM_FLAGS=""
if [ "${SLIM:-1}" = "1" ]; then
	SLIM_DIR=$(tools/slim/overlay.sh)
	trap 'rm -rf "$SLIM_DIR"' EXIT
	SLIM_FLAGS="-modfile $SLIM_DIR/go.mod -overlay $SLIM_DIR/overlay.json"
fi

for t in $TARGETS; do
	os=${t%%/*}; rest=${t#*/}
	arch=${rest%%/*}
	variant=""
	case "$rest" in */*) variant=${rest#*/} ;; esac

	name="sixup-${VERSION}-${os}-${arch}${variant:+-$variant}"
	env_extra=""
	case "$arch" in
		arm)  env_extra="GOARM=${variant:-7}"; [ -z "$variant" ] && name="${name}-7" ;;
		mips|mipsle) env_extra="GOMIPS=${variant:-softfloat}"; [ -z "$variant" ] && name="${name}-softfloat" ;;
	esac

	printf '%-40s' "$name"
	# shellcheck disable=SC2086
	env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" $env_extra \
		go build -trimpath $SLIM_FLAGS -ldflags="$LDFLAGS" -o "$OUT/$name" .
	size=$(wc -c < "$OUT/$name" | tr -d ' ')
	printf '%8d bytes\n' "$size"
done

# The licence of sixup and the notice of the work it derives from travel with the binaries:
# a release is a distribution, and both licences ask for their text to come along.
cp LICENSE NOTICE "$OUT/"

(cd "$OUT" && sha256sum sixup-"${VERSION}"-* > SHA256SUMS 2>/dev/null || shasum -a 256 sixup-"${VERSION}"-* > SHA256SUMS)
echo "written to $OUT/, checksums in $OUT/SHA256SUMS"
