#!/usr/bin/env bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "run this test as root" >&2
	exit 1
fi

mode=${1:-}
case "$mode" in
ordinary-default | ha-default | ha-verbose) ;;
*)
	echo "usage: $0 {ordinary-default|ha-default|ha-verbose}" >&2
	exit 2
	;;
esac

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
bin_dir="$repo_dir/nhrp"
runtime_dir=$(mktemp -d /tmp/opennhrp-log-policy.XXXXXX)
hub_ns=onhrp-log-hub
spoke_ns=onhrp-log-spoke
underlay_ns=onhrp-log-underlay
bridge=onhrp-log-br0
hub_underlay=192.0.2.31
spoke_underlay=192.0.2.32
hub_pid=
spoke_pid=
created=0

stop_pid() {
	local pid=${1:-}
	if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
}

cleanup() {
	set +e
	stop_pid "$spoke_pid"
	stop_pid "$hub_pid"
	if ((created)); then
		ip netns del "$spoke_ns" 2>/dev/null
		ip netns del "$hub_ns" 2>/dev/null
		ip netns del "$underlay_ns" 2>/dev/null
	fi
	rm -rf -- "$runtime_dir"
}
trap cleanup EXIT HUP INT TERM

dump_failure() {
	local status=$?
	for log_file in "$runtime_dir"/*.log; do
		[[ -f $log_file ]] || continue
		echo "--- ${log_file##*/} ---" >&2
		sed -n '1,240p' "$log_file" >&2
	done
	return "$status"
}
trap dump_failure ERR

for namespace in "$hub_ns" "$spoke_ns" "$underlay_ns"; do
	if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
		echo "refusing to overwrite existing namespace $namespace" >&2
		exit 1
	fi
done

modprobe ip_gre
ip netns add "$hub_ns"
ip netns add "$spoke_ns"
ip netns add "$underlay_ns"
created=1
ip -n "$underlay_ns" link set lo up
ip -n "$underlay_ns" link add "$bridge" type bridge
ip -n "$underlay_ns" link set "$bridge" up

create_link() {
	local namespace=$1 host_link=$2 namespace_link=$3 address=$4
	ip link add "$host_link" type veth peer name "$namespace_link"
	ip link set "$host_link" netns "$underlay_ns"
	ip link set "$namespace_link" netns "$namespace"
	ip -n "$underlay_ns" link set "$host_link" master "$bridge"
	ip -n "$underlay_ns" link set "$host_link" up
	ip -n "$namespace" link set lo up
	ip -n "$namespace" link set "$namespace_link" up
	ip -n "$namespace" addr add "$address/24" dev "$namespace_link"
	ip netns exec "$namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
}

create_link "$hub_ns" onhrp-log-h u-hub "$hub_underlay"
create_link "$spoke_ns" onhrp-log-s u-spoke "$spoke_underlay"

ip -n "$hub_ns" tunnel add gre-ha mode gre key 1020 ttl 64
ip -n "$hub_ns" link set gre-ha mtu 1400 up
ip -n "$hub_ns" addr add 10.30.0.1/24 dev gre-ha
ip -n "$spoke_ns" tunnel add gre-ha mode gre key 1020 ttl 64
ip -n "$spoke_ns" link set gre-ha mtu 1400 up
ip -n "$spoke_ns" addr add 10.30.0.2/24 dev gre-ha

mkdir -m 0700 "$runtime_dir/hub-state" "$runtime_dir/spoke-state"
if [[ $mode == ordinary-default ]]; then
	printf 'interface gre-ha\n  holding-time 6\n' >"$runtime_dir/hub.conf"
else
	printf 'interface gre-ha\n  enable-ha member-id hub-primary advertise %s\n' \
		"$hub_underlay" >"$runtime_dir/hub.conf"
fi
printf 'interface gre-ha\n  holding-time 6\n  map 10.30.0.1/24 %s register\n  multicast nhs\n' \
	"$hub_underlay" >"$runtime_dir/spoke.conf"

start_core() {
	local role=$1 namespace=$2 state_dir=$3 config=$4
	local -a verbose=()
	if [[ $mode == ha-verbose ]]; then
		verbose=(-v)
	fi
	ip netns exec "$namespace" "$bin_dir/opennhrp" \
		-a "$runtime_dir/$role.socket" -H "$state_dir" -c "$config" \
		-s /bin/true -p "$runtime_dir/$role.pid" "${verbose[@]}" \
		>>"$runtime_dir/$role.log" 2>&1 &
	printf -v "${role}_pid" '%s' "$!"
	for _ in {1..100}; do
		[[ -S $runtime_dir/$role.socket ]] && return 0
		sleep 0.05
	done
	echo "$role core socket did not appear" >&2
	return 1
}

count_log() {
	local file=$1 pattern=$2
	grep -Fc "$pattern" "$file" 2>/dev/null || true
}

wait_log() {
	local file=$1 pattern=$2
	for _ in {1..600}; do
		grep -Fq "$pattern" "$file" 2>/dev/null && return 0
		sleep 0.05
	done
	echo "log pattern did not appear: $pattern" >&2
	return 1
}

start_core hub "$hub_ns" "$runtime_dir/hub-state" "$runtime_dir/hub.conf"
start_core spoke "$spoke_ns" "$runtime_dir/spoke-state" \
	"$runtime_dir/spoke.conf"

if [[ $mode == ordinary-default ]]; then
	wait_log "$runtime_dir/spoke.log" \
		"Received Registration Reply from 10.30.0.1: success"
	sleep 8
	[[ $(count_log "$runtime_dir/spoke.log" \
		"Sending Registration Request to 10.30.0.1") -eq 1 ]]
	[[ $(count_log "$runtime_dir/spoke.log" \
		"Received Registration Reply from 10.30.0.1: success") -eq 1 ]]
	[[ $(count_log "$runtime_dir/spoke.log" \
		"Peer inserted to multicast list") -eq 1 ]]
	[[ -z $(find "$runtime_dir/hub-state" "$runtime_dir/spoke-state" \
		-mindepth 1 -maxdepth 1 -print -quit) ]]
	[[ -z $(pgrep -P "$hub_pid" || true) ]]
	[[ -z $(pgrep -P "$spoke_pid" || true) ]]
	[[ $(count_log "$runtime_dir/hub.log" "HA candidate") -eq 0 ]]
	[[ $(count_log "$runtime_dir/spoke.log" "HA candidate") -eq 0 ]]

	ip -n "$hub_ns" link set u-hub down
	wait_log "$runtime_dir/spoke.log" "Failed to register to 10.30.0.1"
	ip -n "$hub_ns" link set u-hub up
	"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" \
		cache renew interface gre-ha >/dev/null
	for _ in {1..200}; do
		if [[ $(count_log "$runtime_dir/spoke.log" \
			"Received Registration Reply from 10.30.0.1: success") -ge 2 ]]; then
			break
		fi
		sleep 0.05
	done
	[[ $(count_log "$runtime_dir/spoke.log" \
		"Received Registration Reply from 10.30.0.1: success") -eq 2 ]]
	[[ $(count_log "$runtime_dir/spoke.log" \
		"Peer inserted to multicast list") -eq 1 ]]

	stop_pid "$spoke_pid"
	spoke_pid=
	rm -f -- "$runtime_dir/spoke.socket" "$runtime_dir/spoke.pid"
	printf 'interface gre-ha\n  holding-time 6\n  map 10.30.0.99/24 %s register\n' \
		"$hub_underlay" >"$runtime_dir/spoke.conf"
	start_core spoke "$spoke_ns" "$runtime_dir/spoke-state" \
		"$runtime_dir/spoke.conf"
	wait_log "$runtime_dir/hub.log" \
		"Dropping Registration Request from proto src 10.30.0.2 to non-local proto dst 10.30.0.99"
	sleep 6
	[[ $(count_log "$runtime_dir/hub.log" \
		"Dropping Registration Request from proto src 10.30.0.2 to non-local proto dst 10.30.0.99") -eq 1 ]]
	[[ $(count_log "$runtime_dir/hub.log" \
		"Forwarding packet from nbma src 192.0.2.32, proto src 10.30.0.2 to proto dst 10.30.0.99") -eq 0 ]]
	[[ $(count_log "$runtime_dir/hub.log" \
		"No peer entry for protocol address 10.30.0.99") -eq 0 ]]
elif [[ $mode == ha-default ]]; then
	for _ in {1..300}; do
		state=$("$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" \
			ha show interface gre-ha format json 2>/dev/null || true)
		grep -q '"member":"hub-primary".*"ready":true' <<<"$state" && break
		sleep 0.05
	done
	grep -q '"member":"hub-primary".*"ready":true' <<<"$state"
	state_lines=$(count_log "$runtime_dir/spoke.log" "HA candidate hub-primary")
	ip -n "$underlay_ns" link set onhrp-log-h down
	sleep 0.45
	ip -n "$underlay_ns" link set onhrp-log-h up
	for _ in {1..200}; do
		state=$("$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" \
			ha show interface gre-ha format json 2>/dev/null || true)
		grep -q '"member":"hub-primary".*"ready":true' <<<"$state" && break
		sleep 0.05
	done
	grep -q '"member":"hub-primary".*"ready":true' <<<"$state"
	[[ $(count_log "$runtime_dir/spoke.log" \
		"HA candidate hub-primary") -eq $state_lines ]]
	sleep 65
	[[ $(count_log "$runtime_dir/hub.log" \
		"Received HA Registration Request") -eq 0 ]]
	[[ $(count_log "$runtime_dir/hub.log" \
		"Sending HA Registration Reply") -eq 0 ]]
	[[ $(count_log "$runtime_dir/hub.log" \
		"Received HA Resolution Probe") -eq 0 ]]
	[[ $(count_log "$runtime_dir/spoke.log" \
		"HA candidate hub-primary") -eq $state_lines ]]
else
	wait_log "$runtime_dir/hub.log" "Received HA Registration Request"
	wait_log "$runtime_dir/hub.log" "Sending HA Registration Reply"
	wait_log "$runtime_dir/hub.log" "Received HA Resolution Probe"
fi

printf 'OpenNHRP log policy netns test passed: %s\n' "$mode"
