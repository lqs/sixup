#!/bin/sh
# Produce the files a slim build needs and print a directory containing:
#   go.mod / go.sum   the project go.mod plus replace directives pointing at stubbed
#                     dependency copies, since the module cache cannot be overlaid
#   overlay.json      replacement table for stdlib files, which may be overlaid under GOROOT
# Usage: D=$(tools/slim/overlay.sh); go build -modfile "$D/go.mod" -overlay "$D/overlay.json" .
# Stubs are stored as .go.txt so they are not compiled as Go packages of this project;
# overlay cares about content, not file names.
# The stubs cut the init and option-table references that drag sha3, aes, dhcpv4, idna and
# bidi into the binary; see the header of each stub file.
set -eu
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
HERE=$ROOT/tools/slim
GOROOT=$(go env GOROOT)
D=$(mktemp -d -t sixup-slim.XXXXXX)

# stubbed dependency copies
DHCP=$(go list -m -f '{{.Dir}}' github.com/insomniacslk/dhcp)
XNET=$(go list -m -f '{{.Dir}}' golang.org/x/net)
cp -R "$DHCP" "$D/dhcp"; cp -R "$XNET" "$D/xnet"; chmod -R u+w "$D/dhcp" "$D/xnet"
cp "$HERE/dhcpv6_option_dhcpv4_msg.go.txt" "$D/dhcp/dhcpv6/option_dhcpv4_msg.go"
rm -f "$D/dhcp/dhcpv6/option_dhcpv4_msg_test.go"
rm -f "$D/xnet/idna/"*.go
cp "$HERE/idna.go.txt" "$D/xnet/idna/idna.go"

# go.mod: the original plus replace directives
cp go.mod "$D/go.mod"; cp go.sum "$D/go.sum"
{
	printf '\nreplace github.com/insomniacslk/dhcp => %s\n' "$D/dhcp"
	printf 'replace golang.org/x/net => %s\n' "$D/xnet"
} >> "$D/go.mod"

# stdlib overlay
cat > "$D/overlay.json" <<JSON
{"Replace":{
"$GOROOT/src/crypto/internal/fips140/sha3/cast.go":"$HERE/sha3_cast.go.txt",
"$GOROOT/src/crypto/internal/fips140/aes/cast.go":"$HERE/aes_cast.go.txt",
"$GOROOT/src/crypto/internal/fips140/aes/gcm/cast.go":"$HERE/gcm_cast.go.txt",
"$GOROOT/src/crypto/internal/fips140/drbg/cast.go":"$HERE/drbg_cast.go.txt",
"$GOROOT/src/crypto/internal/fips140/drbg/ctrdrbg.go":"$HERE/drbg_ctrdrbg.go.txt"
}}
JSON
echo "$D"
