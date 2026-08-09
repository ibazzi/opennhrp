#!/bin/sh

set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_stamp=$(date -u +%Y%m%dT%H%M%SZ)
revision=$(git -C "$repo_dir" rev-parse --short HEAD)
build_id="${build_stamp}-${revision}-pure-mgre-ha"
output_dir=${1:-/tmp}
bundle_root=$(mktemp -d /tmp/opennhrp-ha-bundle.XXXXXX)
bundle_dir="$bundle_root/$build_id"
archive="$output_dir/opennhrp-ha-test-$build_id.tar.gz"

cleanup() {
	rm -rf -- "$bundle_root"
}
trap cleanup EXIT HUP INT TERM

make -C "$repo_dir" test
make -C "$repo_dir" check-format

install -d "$bundle_dir/bin" "$bundle_dir/lib" "$bundle_dir/config"
install -m 0755 "$repo_dir/nhrp/opennhrp" "$bundle_dir/bin/opennhrp.bin"
install -m 0755 "$repo_dir/nhrp/opennhrpctl" "$bundle_dir/bin/opennhrpctl"
install -m 0755 "$repo_dir/nhrp/opennhrp-ha" "$bundle_dir/bin/opennhrp-ha.bin"

cares_path=$(ldd "$repo_dir/nhrp/opennhrp" | awk '$1 == "libcares.so.2" { print $3 }')
if [ -z "$cares_path" ] || [ ! -f "$cares_path" ]; then
	echo "unable to locate libcares.so.2" >&2
	exit 1
fi
install -m 0755 "$cares_path" "$bundle_dir/lib/libcares.so.2"

crypto_path=$(ldd "$repo_dir/nhrp/opennhrp-ha" | awk '$1 == "libcrypto.so.3" { print $3 }')
if [ -z "$crypto_path" ] || [ ! -f "$crypto_path" ]; then
	echo "unable to locate libcrypto.so.3" >&2
	exit 1
fi
install -m 0755 "$crypto_path" "$bundle_dir/lib/libcrypto.so.3"

install -m 0755 "$repo_dir/scripts/opennhrp-test-wrapper.in" \
	"$bundle_dir/bin/opennhrp"
chmod 0755 "$bundle_dir/bin/opennhrp"
install -m 0755 "$repo_dir/scripts/opennhrp-test-wrapper.in" \
	"$bundle_dir/bin/opennhrp-ha"
chmod 0755 "$bundle_dir/bin/opennhrp-ha"

install -m 0644 "$repo_dir/tests/real/hub-primary.conf" \
	"$bundle_dir/config/hub-primary.conf"
install -m 0644 "$repo_dir/tests/real/hub-backup1.conf" \
	"$bundle_dir/config/hub-backup1.conf"
install -m 0644 "$repo_dir/tests/real/spoke.conf" \
	"$bundle_dir/config/spoke.conf"
(
	cd "$bundle_dir"
	sha256sum bin/opennhrp.bin bin/opennhrpctl bin/opennhrp-ha.bin \
		lib/libcares.so.2 lib/libcrypto.so.3 config/*.conf >SHA256SUMS
)
tar -C "$bundle_root" -czf "$archive" "$build_id"
(
	cd "$output_dir"
	sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256"
)

printf '%s\n' "$archive"
