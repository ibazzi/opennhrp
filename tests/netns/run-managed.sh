#!/usr/bin/env bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "run this test as root" >&2
	exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
bin_dir="$repo_dir/nhrp"
runtime_dir=$(mktemp -d /tmp/opennhrp-ha-managed-netns.XXXXXX)
hub1_ns=onhrp-mha-hub1
hub2_ns=onhrp-mha-hub2
hub3_ns=onhrp-mha-hub3
spoke_ns=onhrp-mha-spoke
private_spoke_ns=onhrp-mha-private-spoke
underlay_ns=onhrp-mha-underlay
bridge=onhrp-mha-br0
hub1_underlay=192.0.2.11
hub2_underlay=192.0.2.12
spoke_underlay=192.0.2.13
hub3_underlay=192.0.2.14
hub3_configured_nbma=10.0.4.20
hub1_local_nbma=192.0.2.21
hub2_local_nbma=192.0.2.22
hub1_reloaded_nbma=192.0.2.23
hub1_private_nbma=10.0.4.17
hub2_private_nbma=10.0.4.18
hub2_extra_nbma=192.0.2.24
private_spoke_underlay=10.0.4.19
hub1_pid=
hub2_pid=
hub3_pid=
spoke_pid=
private_spoke_pid=
witness_spoke_pid=
witness_monitor_pid=
created=0

log() {
	printf '[%s] %s\n' "$(date +%H:%M:%S.%3N)" "$*"
}

stop_pid() {
	local pid=${1:-}
	if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
}

cleanup() {
	set +e
	stop_pid "$witness_monitor_pid"
	stop_pid "$witness_spoke_pid"
	stop_pid "$spoke_pid"
	stop_pid "$private_spoke_pid"
	stop_pid "$hub3_pid"
	stop_pid "$hub2_pid"
	stop_pid "$hub1_pid"
	if ((created)); then
		ip netns del "$spoke_ns" 2>/dev/null
		ip netns del "$private_spoke_ns" 2>/dev/null
		ip netns del "$hub3_ns" 2>/dev/null
		ip netns del "$hub2_ns" 2>/dev/null
		ip netns del "$hub1_ns" 2>/dev/null
		ip netns del "$underlay_ns" 2>/dev/null
	fi
	if [[ ${KEEP_FAILED_ARTIFACTS:-0} == 1 ]]; then
		printf 'preserved test artifacts: %s\n' "$runtime_dir" >&2
	else
		rm -rf -- "$runtime_dir"
	fi
}
trap cleanup EXIT HUP INT TERM

for namespace in "$hub1_ns" "$hub2_ns" "$hub3_ns" "$spoke_ns" \
	"$private_spoke_ns" "$underlay_ns"; do
	if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
		echo "refusing to overwrite existing namespace $namespace" >&2
		exit 1
	fi
done

modprobe ip_gre
ip netns add "$hub1_ns"
ip netns add "$hub2_ns"
ip netns add "$hub3_ns"
ip netns add "$spoke_ns"
ip netns add "$private_spoke_ns"
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
	ip netns exec "$namespace" sysctl -qw net.ipv4.ip_forward=1
	ip netns exec "$namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
}

create_link "$hub1_ns" omha-h1 u-hub1 "$hub1_underlay"
create_link "$hub2_ns" omha-h2 u-hub2 "$hub2_underlay"
create_link "$hub3_ns" omha-h3 u-hub3 "$hub3_underlay"
create_link "$spoke_ns" omha-sp u-spoke "$spoke_underlay"
create_link "$private_spoke_ns" omha-ps u-private "$private_spoke_underlay"
ip -n "$hub1_ns" addr add "$hub1_local_nbma/24" dev u-hub1
ip -n "$hub1_ns" addr add "$hub1_reloaded_nbma/24" dev u-hub1
ip -n "$hub2_ns" addr add "$hub2_local_nbma/24" dev u-hub2
ip -n "$hub1_ns" addr add "$hub1_private_nbma/24" dev u-hub1
ip -n "$hub2_ns" addr add "$hub2_private_nbma/24" dev u-hub2
ip -n "$hub2_ns" addr add "$hub2_extra_nbma/24" dev u-hub2
ip -n "$hub3_ns" addr add "$hub3_configured_nbma/24" dev u-hub3

create_mgre() {
	local namespace=$1 address=$2
	ip -n "$namespace" tunnel add gre-ha mode gre key 1020 ttl 64
	ip -n "$namespace" link set gre-ha mtu 1400 up
	ip -n "$namespace" addr add "$address/24" dev gre-ha
}

create_mgre "$hub1_ns" 10.20.0.1
create_mgre "$hub2_ns" 10.20.0.1
create_mgre "$hub3_ns" 10.20.0.1
create_mgre "$spoke_ns" 10.20.0.2
create_mgre "$private_spoke_ns" 10.20.0.3
for namespace in "$hub1_ns" "$hub2_ns" "$hub3_ns"; do
	ip -n "$namespace" addr add 198.51.100.250/32 dev lo
	ip -n "$namespace" addr add 198.51.100.251/32 dev lo
done
ip -n "$hub1_ns" addr add 198.18.20.1/32 dev lo
ip -n "$hub2_ns" addr add 198.18.20.1/32 dev lo
ip -n "$hub3_ns" addr add 198.18.20.1/32 dev lo
ip -n "$spoke_ns" route add 10.20.0.0/24 dev gre-ha scope link table 220
ip -n "$spoke_ns" route add default via 10.20.0.1 dev gre-ha table 220
ip -n "$spoke_ns" rule add priority 10220 from 10.20.0.2/32 lookup 220
ip -n "$private_spoke_ns" route add 10.20.0.0/24 dev gre-ha scope link table 220
ip -n "$private_spoke_ns" route add default via 10.20.0.1 dev gre-ha table 220
ip -n "$private_spoke_ns" rule add priority 10220 from 10.20.0.3/32 lookup 220

mkdir -m 0700 "$runtime_dir/hub1-state" "$runtime_dir/hub2-state" \
	"$runtime_dir/hub3-state" "$runtime_dir/spoke-state" \
	"$runtime_dir/private-spoke-state" "$runtime_dir/witness-spoke-state"
printf 'interface gre-ha\n  enable-ha member-id hub-primary advertise %s advertise %s\n  ha-health-target 198.51.100.250\n  ha-health-target 198.51.100.251\n' \
  "$hub1_underlay" "$hub1_private_nbma" >"$runtime_dir/hub1.conf"
printf 'interface gre-ha\n  enable-ha\n  ha-health-target 198.51.100.250\n  ha-health-target 198.51.100.251\n' >"$runtime_dir/hub2.conf"
printf 'interface gre-ha\n  enable-ha\n  ha-health-target 198.51.100.250\n  ha-health-target 198.51.100.251\n' >"$runtime_dir/hub3.conf"

start_core() {
	local role=$1 namespace=$2 state_dir=$3 config=$4
	ip netns exec "$namespace" env OPENNHRP_HA_STATE_DIR="$state_dir" \
		OPENNHRP_HA_KEY_DIR="$runtime_dir" \
		"$bin_dir/opennhrp" -a "$runtime_dir/$role.socket" -H "$state_dir" \
		-c "$config" -s /bin/true -p "$runtime_dir/$role.pid" -v \
		>>"$runtime_dir/$role.log" 2>&1 &
	printf -v "${role}_pid" '%s' "$!"
	for _ in {1..100}; do
		[[ -S $runtime_dir/$role.socket ]] && return 0
		sleep 0.05
	done
	echo "$role core socket did not appear" >&2
	return 1
}

wait_coordinator() {
	local role=$1
	for _ in {1..100}; do
		[[ -S $runtime_dir/$role-ha.socket ]] && return 0
		sleep 0.05
	done
	echo "$role coordinator socket did not appear" >&2
	return 1
}

log "auto-initializing Primary from enable-ha"
start_core hub1 "$hub1_ns" "$runtime_dir/hub1-state" "$runtime_dir/hub1.conf"
wait_coordinator hub1

log "creating interface-independent Invites and joining two Standbys"
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha invite create --member-id expired-invite-test \
	--expires 1s --format plain >/dev/null
sleep 2
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha invite create --member-id expired-invite-test \
	--format plain >/dev/null
invite=$(OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha invite create --member-id hub-backup1 \
	--format plain)
printf '%s\n' "$invite" | ip netns exec "$hub2_ns" env \
	OPENNHRP_HA_STATE_DIR="$runtime_dir/hub2-state" \
	"$bin_dir/opennhrpctl" ha join --interface gre-ha \
	--advertise-address "$hub2_underlay" \
	--advertise-address "$hub2_private_nbma" >"$runtime_dir/join.txt"
unset invite
grep -q 'Hub hub-backup1 joined' "$runtime_dir/join.txt"

start_core hub2 "$hub2_ns" "$runtime_dir/hub2-state" "$runtime_dir/hub2.conf"
wait_coordinator hub2

cluster_json() {
	"$bin_dir/opennhrpctl" -a "$runtime_dir/hub1-ha.socket" \
		ha cluster show --format json 2>/dev/null || true
}

for _ in {1..200}; do
	cluster=$(cluster_json)
	if grep -q '"member":"hub-backup1".*"state":"active"' <<<"$cluster"; then
		break
	fi
	sleep 0.05
done
cluster=$(cluster_json)
grep -q '"member":"hub-backup1".*"state":"active"' <<<"$cluster"

hub_cluster() {
	local role=$1
	"$bin_dir/opennhrpctl" -a "$runtime_dir/$role-ha.socket" \
		ha cluster show --format json 2>/dev/null || true
}

hub_core_role() {
	local role=$1
	"$bin_dir/opennhrpctl" -a "$runtime_dir/$role.socket" \
		ha hub show interface gre-ha format json 2>/dev/null |
		grep -o '"role":"[^"]*"' | head -n 1 | cut -d'"' -f4
}

wait_core_role() {
	local role=$1 expected=$2
	for _ in {1..120}; do
		[[ $(hub_core_role "$role") == "$expected" ]] && return 0
		sleep 0.05
	done
	printf '%s core role is %s, expected %s\n' \
		"$role" "$(hub_core_role "$role")" "$expected" >&2
	hub_cluster "$role" >&2
	return 1
}

assert_no_dual_serviceable_leader() {
	local first second
	first=$(hub_core_role hub1)
	second=$(hub_core_role hub2)
	if [[ $first == leader && $second == leader ]]; then
		echo "both Hubs are serviceable Leaders" >&2
		return 1
	fi
}

witness_command() {
	local role=$1
	shift
	"$bin_dir/opennhrpctl" -a "$runtime_dir/$role-ha.socket" "$@" \
		>/dev/null
}

monitor_witness_roles() {
	local first second
	while :; do
		first=$(hub_core_role hub1)
		second=$(hub_core_role hub2)
		if [[ $first == leader && $second == leader ]]; then
			printf 'dual serviceable Leaders observed\n' \
				>>"$runtime_dir/witness-dual-role.txt"
			return
		fi
		sleep 0.05
	done
}

witness_spoke_ha_show() {
	"$bin_dir/opennhrpctl" -a "$runtime_dir/witness_spoke.socket" \
		ha show interface gre-ha format json 2>/dev/null || true
}

cp "$runtime_dir/hub1-state/keys" "$runtime_dir/gre-ha.keys"
chmod 0600 "$runtime_dir/gre-ha.keys"
cat >"$runtime_dir/witness-spoke.conf" <<EOF
interface gre-ha
  holding-time 60
  map 10.20.0.1/32 $hub1_underlay local-nbma $hub1_local_nbma register
  ha-local-nbma hub-backup1 $hub2_local_nbma
EOF
start_core witness_spoke "$spoke_ns" "$runtime_dir/witness-spoke-state" \
	"$runtime_dir/witness-spoke.conf"
for _ in {1..300}; do
	witness_spoke_state=$(witness_spoke_ha_show)
	if grep -q '"member":"hub-primary".*"ready":true' \
		<<<"$witness_spoke_state" &&
		grep -q '"member":"hub-backup1".*"ready":true' \
			<<<"$witness_spoke_state" &&
		grep -q '"active_member":"hub-primary"' <<<"$witness_spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-primary".*"ready":true' <<<"$witness_spoke_state"
grep -q '"member":"hub-backup1".*"ready":true' <<<"$witness_spoke_state"
grep -q '"active_member":"hub-primary"' <<<"$witness_spoke_state"

log "validating optional two-Hub Witness activation and quorum fencing"
grep -q '"mode":"legacy"' <<<"$(hub_cluster hub1)"
grep -q '"mode":"legacy"' <<<"$(hub_cluster hub2)"
for _ in {1..400}; do
	hub1_cluster=$(hub_cluster hub1)
	hub2_cluster=$(hub_cluster hub2)
	if grep -q '"member":"hub-backup1".*"connected":true.*"authenticated":true' \
		<<<"$hub1_cluster" &&
		grep -q '"member":"hub-primary".*"connected":true.*"authenticated":true' \
			<<<"$hub2_cluster" &&
		grep -q '"member":"hub-backup1".*"state":"active"' \
			<<<"$hub2_cluster" &&
		grep -q '"capable":true' <<<"$hub1_cluster" &&
		grep -q '"capable":true' <<<"$hub2_cluster" &&
		grep -q '"service_available":true' <<<"$hub1_cluster" &&
		grep -q '"service_available":true' <<<"$hub2_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-backup1".*"connected":true.*"authenticated":true' \
	<<<"$hub1_cluster"
grep -q '"member":"hub-primary".*"connected":true.*"authenticated":true' \
	<<<"$hub2_cluster"
grep -q '"member":"hub-backup1".*"state":"active"' <<<"$hub2_cluster"
grep -q '"capable":true' <<<"$hub1_cluster"
grep -q '"capable":true' <<<"$hub2_cluster"
grep -q '"service_available":true' <<<"$hub1_cluster"
grep -q '"service_available":true' <<<"$hub2_cluster"
ip -n "$underlay_ns" link set omha-h1 down
wait_core_role hub1 leader
wait_core_role hub2 leader

log "preparing a newer equivalent manifest on the future Follower"
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha member set hub-backup1 \
	--advertise-address 192.0.2.99 >/dev/null
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha member set hub-backup1 \
	--advertise-address "$hub2_underlay" >/dev/null

witness_epoch=00112233445566778899aabbccddeeff
witness_command hub1 ha witness prepare epoch "$witness_epoch"
wait_core_role hub1 standby
wait_core_role hub2 leader
: >"$runtime_dir/witness-dual-role.txt"
monitor_witness_roles &
witness_monitor_pid=$!
witness_command hub2 ha witness prepare epoch "$witness_epoch"
wait_core_role hub2 standby
assert_no_dual_serviceable_leader
witness_command hub1 ha witness activate epoch "$witness_epoch"
wait_core_role hub1 standby
witness_command hub2 ha witness activate epoch "$witness_epoch"
wait_core_role hub2 standby

hub1_term=$(hub_cluster hub1 | grep -o '"term":[0-9]*' | head -n 1 | cut -d: -f2)
hub2_term=$(hub_cluster hub2 | grep -o '"term":[0-9]*' | head -n 1 | cut -d: -f2)
witness_term=$((hub1_term > hub2_term ? hub1_term + 1 : hub2_term + 1))
witness_sequence=1
for role in hub1 hub2; do
	witness_command "$role" ha witness lease epoch "$witness_epoch" \
		term "$witness_term" holder hub-primary sequence "$witness_sequence" \
		ttl-ms 3000
done
wait_core_role hub1 leader
wait_core_role hub2 standby
assert_no_dual_serviceable_leader

log "validating Manager+Hub partition self-fencing and <=5s recovery"
outage_started_ms=$(date +%s%3N)
wait_core_role hub1 standby
wait_core_role hub2 standby
witness_sequence=$((witness_sequence + 1))
hub2_term=$(hub_cluster hub2 | grep -o '"term":[0-9]*' | head -n 1 | cut -d: -f2)
witness_term=$((hub2_term + 1))
for role in hub1 hub2; do
	witness_command "$role" ha witness lease epoch "$witness_epoch" \
		term "$witness_term" holder hub-backup1 sequence "$witness_sequence" \
		ttl-ms 3000
done
wait_core_role hub2 leader
hub1_term=$(hub_cluster hub1 | grep -o '"term":[0-9]*' | head -n 1 | cut -d: -f2)
sleep 0.5
hub1_cluster=$(hub_cluster hub1)
grep -q '"leader":"hub-backup1"' <<<"$hub1_cluster"
grep -q '"term":'"$hub1_term" <<<"$hub1_cluster"
witness_spoke_recovered=0
for _ in {1..20}; do
	witness_spoke_state=$(witness_spoke_ha_show)
	if grep -q '"active_member":"hub-backup1"' <<<"$witness_spoke_state" &&
		ip netns exec "$spoke_ns" ping -I 10.20.0.2 -c 1 -W 1 \
			198.18.20.1 >/dev/null 2>&1; then
		witness_spoke_recovered=1
		break
	fi
	sleep 0.05
done
((witness_spoke_recovered))
recovery_elapsed_ms=$(($(date +%s%3N) - outage_started_ms))
((recovery_elapsed_ms <= 5000))
assert_no_dual_serviceable_leader

log "validating stale follower manifest keeps the HA session connected"
for _ in {1..40}; do
	hub1_cluster=$(hub_cluster hub1)
	hub2_cluster=$(hub_cluster hub2)
	hub1_revision=$(grep -o '"manifest_revision":[0-9]*' \
		<<<"$hub1_cluster" | cut -d: -f2)
	hub2_revision=$(grep -o '"manifest_revision":[0-9]*' \
		<<<"$hub2_cluster" | cut -d: -f2)
	((hub1_revision > hub2_revision)) && break
	sleep 0.05
done
((hub1_revision > hub2_revision))

log "validating peer vote and coordinated fallback after Manager loss"
ip -n "$underlay_ns" link set omha-h1 up
for _ in {1..200}; do
	hub1_cluster=$(hub_cluster hub1)
	hub2_cluster=$(hub_cluster hub2)
	if grep -q '"leader":"hub-backup1"' <<<"$hub1_cluster" &&
		grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster" &&
		grep -q '"peer_vote":true' <<<"$hub2_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"peer_vote":true' <<<"$hub2_cluster"
for _ in {1..20}; do
	hub1_cluster=$(hub_cluster hub1)
	hub2_cluster=$(hub_cluster hub2)
	grep -q '"member":"hub-backup1".*"connected":true.*"authenticated":true' \
		<<<"$hub1_cluster"
	grep -q '"member":"hub-primary".*"connected":true.*"authenticated":true' \
		<<<"$hub2_cluster"
	sleep 0.05
done
hub1_digest=$(grep -o '"digest":"[0-9a-f]*"' <<<"$hub1_cluster" | head -n 1)
hub2_digest=$(grep -o '"digest":"[0-9a-f]*"' <<<"$hub2_cluster" | head -n 1)
[[ $hub1_digest == "$hub2_digest" ]]
hub1_revision=$(grep -o '"manifest_revision":[0-9]*' \
	<<<"$hub1_cluster" | cut -d: -f2)
hub2_revision=$(grep -o '"manifest_revision":[0-9]*' \
	<<<"$hub2_cluster" | cut -d: -f2)
((hub2_revision >= hub1_revision))
wait_core_role hub2 leader
for _ in {1..800}; do
	hub1_cluster=$(hub_cluster hub1)
	hub2_cluster=$(hub_cluster hub2)
	if grep -q '"mode":"legacy"' <<<"$hub1_cluster" &&
		grep -q '"mode":"legacy"' <<<"$hub2_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"mode":"legacy"' <<<"$hub1_cluster"
grep -q '"mode":"legacy"' <<<"$hub2_cluster"
stop_pid "$witness_monitor_pid"
witness_monitor_pid=
if [[ -s $runtime_dir/witness-dual-role.txt ]]; then
	cat "$runtime_dir/witness-dual-role.txt" >&2
	exit 1
fi
wait_core_role hub2 leader
"$bin_dir/opennhrpctl" -a "$runtime_dir/hub2-ha.socket" \
	ha failback request force >/dev/null
for _ in {1..200}; do
	cluster=$(hub_cluster hub1)
	hub2_cluster=$(hub_cluster hub2)
	if grep -q '"leader":"hub-primary"' <<<"$cluster" &&
		grep -q '"leader":"hub-primary"' <<<"$hub2_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"leader":"hub-primary"' <<<"$cluster"
grep -q '"leader":"hub-primary"' <<<"$hub2_cluster"
stop_pid "$hub2_pid"
hub2_pid=
rm -f -- "$runtime_dir/hub2.socket" "$runtime_dir/hub2-ha.socket" \
	"$runtime_dir/hub2.pid"
start_core hub2 "$hub2_ns" "$runtime_dir/hub2-state" "$runtime_dir/hub2.conf"
wait_coordinator hub2
for _ in {1..200}; do
	cluster=$(hub_cluster hub1)
	hub2_cluster=$(hub_cluster hub2)
	if grep -q '"leader":"hub-primary"' <<<"$cluster" &&
		grep -q '"leader":"hub-primary"' <<<"$hub2_cluster" &&
		grep -q '"member":"hub-backup1".*"authenticated":true' \
			<<<"$cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-backup1".*"authenticated":true' <<<"$cluster"
stop_pid "$witness_spoke_pid"
witness_spoke_pid=

log "validating restarted Standby cannot displace a running Primary"
for _ in {1..200}; do
	hub2_cluster=$("$bin_dir/opennhrpctl" \
		-a "$runtime_dir/hub2-ha.socket" ha cluster show --format json \
		2>/dev/null || true)
	if grep -q '"member":"hub-backup1".*"state":"active"' \
		<<<"$hub2_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-backup1".*"state":"active"' <<<"$hub2_cluster"
stop_pid "$hub1_pid"
hub1_pid=
rm -f -- "$runtime_dir/hub1.socket" "$runtime_dir/hub1-ha.socket" \
	"$runtime_dir/hub1.pid"
for _ in {1..200}; do
	hub2_cluster=$("$bin_dir/opennhrpctl" \
		-a "$runtime_dir/hub2-ha.socket" ha cluster show --format json \
		2>/dev/null || true)
	grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster" && break
	sleep 0.05
done
grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster"

log "validating failback transfer resists stale Backup leader frames"
start_core hub1 "$hub1_ns" "$runtime_dir/hub1-state" "$runtime_dir/hub1.conf"
wait_coordinator hub1
for _ in {1..200}; do
	failback_state=$("$bin_dir/opennhrpctl" \
		-a "$runtime_dir/hub2-ha.socket" ha failback show --format json \
		2>/dev/null || true)
	if grep -q '"primary_healthy":true' <<<"$failback_state" &&
		grep -q '"primary_synchronized":true' <<<"$failback_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"primary_healthy":true' <<<"$failback_state"
grep -q '"primary_synchronized":true' <<<"$failback_state"
"$bin_dir/opennhrpctl" -a "$runtime_dir/hub2-ha.socket" \
	ha failback request force >/dev/null
for _ in {1..200}; do
	cluster=$(cluster_json)
	hub2_cluster=$("$bin_dir/opennhrpctl" \
		-a "$runtime_dir/hub2-ha.socket" ha cluster show --format json \
		2>/dev/null || true)
	if grep -q '"leader":"hub-primary"' <<<"$cluster" &&
		grep -q '"leader":"hub-primary"' <<<"$hub2_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"leader":"hub-primary"' <<<"$cluster"
grep -q '"leader":"hub-primary"' <<<"$hub2_cluster"
stop_pid "$hub1_pid"
hub1_pid=
rm -f -- "$runtime_dir/hub1.socket" "$runtime_dir/hub1-ha.socket" \
	"$runtime_dir/hub1.pid"
for _ in {1..200}; do
	hub2_cluster=$("$bin_dir/opennhrpctl" \
		-a "$runtime_dir/hub2-ha.socket" ha cluster show --format json \
		2>/dev/null || true)
	grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster" && break
	sleep 0.05
done
grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster"

stop_pid "$hub2_pid"
hub2_pid=
rm -f -- "$runtime_dir/hub2.socket" "$runtime_dir/hub2-ha.socket" \
	"$runtime_dir/hub2.pid"

start_core hub1 "$hub1_ns" "$runtime_dir/hub1-state" "$runtime_dir/hub1.conf"
wait_coordinator hub1
cluster=$(cluster_json)
grep -q '"leader":"hub-primary"' <<<"$cluster"
start_core hub2 "$hub2_ns" "$runtime_dir/hub2-state" "$runtime_dir/hub2.conf"
wait_coordinator hub2
for _ in {1..200}; do
	cluster=$(cluster_json)
	grep -q '"leader":"hub-primary"' <<<"$cluster"
	hub2_cluster=$("$bin_dir/opennhrpctl" \
		-a "$runtime_dir/hub2-ha.socket" ha cluster show --format json \
		2>/dev/null || true)
	if grep -q '"leader":"hub-primary"' <<<"$hub2_cluster" &&
		grep -q '"member":"hub-primary".*"connected":true.*"authenticated":true' \
			<<<"$hub2_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"leader":"hub-primary"' <<<"$cluster"
grep -q '"leader":"hub-primary"' <<<"$hub2_cluster"

log "adding a Standby configured endpoint through the Leader"
printf 'interface gre-ha\n  enable-ha advertise %s advertise %s advertise %s\n  ha-health-target 198.51.100.250\n  ha-health-target 198.51.100.251\n' \
  "$hub2_underlay" "$hub2_private_nbma" "$hub2_extra_nbma" \
  >"$runtime_dir/hub2.conf"
"$bin_dir/opennhrpctl" -a "$runtime_dir/hub2.socket" reload \
  >"$runtime_dir/hub2-reload.txt"
for _ in {1..200}; do
	cluster=$(cluster_json)
	if grep -q '"member":"hub-backup1".*"address":"'"$hub2_underlay"'","origin":"configured".*"address":"'"$hub2_private_nbma"'","origin":"configured".*"address":"'"$hub2_extra_nbma"'","origin":"configured"' \
		<<<"$cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-backup1".*"address":"'"$hub2_underlay"'","origin":"configured".*"address":"'"$hub2_private_nbma"'","origin":"configured".*"address":"'"$hub2_extra_nbma"'","origin":"configured"' \
	<<<"$cluster"

invite=$(OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha invite create --member-id hub-backup2 \
	--format plain)
printf '%s\n' "$invite" | ip netns exec "$hub3_ns" env \
	OPENNHRP_HA_STATE_DIR="$runtime_dir/hub3-state" \
	"$bin_dir/opennhrpctl" ha join --interface gre-ha \
	>"$runtime_dir/join2.txt"
unset invite
grep -q 'Hub hub-backup2 joined' "$runtime_dir/join2.txt"
start_core hub3 "$hub3_ns" "$runtime_dir/hub3-state" "$runtime_dir/hub3.conf"
wait_coordinator hub3

for _ in {1..200}; do
	cluster=$(cluster_json)
	if grep -q '"member":"hub-backup2".*"state":"active"' <<<"$cluster"; then
		break
	fi
	sleep 0.05
done
cluster=$(cluster_json)
grep -q '"member":"hub-backup2".*"state":"active"' <<<"$cluster"
grep -q '"member":"hub-backup2".*"address":"'"$hub3_underlay"'","origin":"observed"' \
	<<<"$cluster"
printf '%s\n' "$cluster" >"$runtime_dir/cluster.active.json"

log "validating disabled member can be enabled and catch up"
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha member disable hub-backup2 \
	>"$runtime_dir/member-disable.txt"
grep -q 'Member hub-backup2 disable completed' \
	"$runtime_dir/member-disable.txt"
for _ in {1..200}; do
	cluster=$(cluster_json)
	grep -q '"member":"hub-backup2".*"state":"disabled"' \
		<<<"$cluster" && break
	sleep 0.05
done
grep -q '"member":"hub-backup2".*"state":"disabled"' <<<"$cluster"
for role in hub2 hub3; do
	for _ in {1..200}; do
		cluster=$(hub_cluster "$role")
		grep -q '"member":"hub-backup2".*"state":"disabled"' \
			<<<"$cluster" && break
		sleep 0.05
	done
	grep -q '"member":"hub-backup2".*"state":"disabled"' <<<"$cluster"
done
hub2_reload_before=$(grep -c 'Reloading managed HA state' \
	"$runtime_dir/hub2.log" || true)
hub3_reload_before=$(grep -c 'Reloading managed HA state' \
	"$runtime_dir/hub3.log" || true)
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha member enable hub-backup2 \
	>"$runtime_dir/member-enable.txt"
grep -q 'Member hub-backup2 enable completed' "$runtime_dir/member-enable.txt"
for _ in {1..200}; do
	cluster=$(cluster_json)
	grep -q '"member":"hub-backup2".*"state":"active"' \
		<<<"$cluster" && break
	sleep 0.05
done
grep -q '"member":"hub-backup2".*"state":"active"' <<<"$cluster"
for role in hub2 hub3; do
	for _ in {1..200}; do
		cluster=$("$bin_dir/opennhrpctl" -a "$runtime_dir/$role-ha.socket" \
			ha cluster show --format json 2>/dev/null || true)
		grep -q '"member":"hub-backup2".*"state":"active"' \
			<<<"$cluster" && break
		sleep 0.05
	done
	grep -q '"member":"hub-backup2".*"state":"active"' <<<"$cluster"
done
[[ $(grep -c 'Reloading managed HA state' "$runtime_dir/hub2.log" || true) \
	-eq $((hub2_reload_before + 1)) ]]
[[ $(grep -c 'Reloading managed HA state' "$runtime_dir/hub3.log" || true) \
	-eq $((hub3_reload_before + 1)) ]]

log "validating runtime member endpoint replacement order"
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha member set hub-backup2 \
	--advertise-address "$hub3_configured_nbma" \
	>"$runtime_dir/member-set.txt"
grep -q 'Member hub-backup2 set completed' "$runtime_dir/member-set.txt"
printf 'ha managed reload\n' | nc -N -U "$runtime_dir/hub1.socket" \
	>"$runtime_dir/managed-reload.txt"
grep -q '^Status: ok' "$runtime_dir/managed-reload.txt"
for _ in {1..200}; do
	cluster=$(cluster_json)
	if grep -q '"member":"hub-backup2".*"address":"'"$hub3_configured_nbma"'","origin":"configured".*"address":"'"$hub3_underlay"'","origin":"observed"' \
		<<<"$cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-backup2".*"address":"'"$hub3_configured_nbma"'","origin":"configured".*"address":"'"$hub3_underlay"'","origin":"observed"' \
	<<<"$cluster"

cp "$runtime_dir/hub1-state/keys" "$runtime_dir/gre-ha.keys"
chmod 0600 "$runtime_dir/gre-ha.keys"
cat >"$runtime_dir/spoke.conf" <<EOF
interface gre-ha
  holding-time 60
  map 10.20.0.1/32 $hub1_underlay local-nbma $hub1_local_nbma register
  ha-local-nbma hub-backup1 $hub2_local_nbma
EOF
cat >"$runtime_dir/private-spoke.conf" <<EOF
interface gre-ha
  map 10.20.0.1/32 $hub1_private_nbma register
EOF
grep -q '^  map 10.20.0.1/32 ' "$runtime_dir/spoke.conf"
if grep -Eq 'ha-(cluster-id|member-id|advertise|map)|generation' \
	"$runtime_dir"/hub?.conf "$runtime_dir/spoke.conf" \
	"$runtime_dir/private-spoke.conf"; then
	echo "legacy HA configuration leaked into managed test" >&2
	exit 1
fi

start_core spoke "$spoke_ns" "$runtime_dir/spoke-state" \
	"$runtime_dir/spoke.conf"
start_core private_spoke "$private_spoke_ns" \
	"$runtime_dir/private-spoke-state" "$runtime_dir/private-spoke.conf"

spoke_ha_show() {
	"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" \
		ha show interface gre-ha format json 2>/dev/null || true
}

private_spoke_ha_show() {
	"$bin_dir/opennhrpctl" -a "$runtime_dir/private_spoke.socket" \
		ha show interface gre-ha format json 2>/dev/null || true
}

wait_spoke_neighbor() {
	local expected=$1

	for _ in {1..100}; do
		if ip -n "$spoke_ns" neigh show 10.20.0.1 dev gre-ha |
			grep -q "lladdr $expected"; then
			return 0
		fi
		sleep 0.05
	done
	ip -n "$spoke_ns" neigh show 10.20.0.1 dev gre-ha >&2
	return 1
}

wait_private_spoke_neighbor() {
	local expected=$1

	for _ in {1..100}; do
		if ip -n "$private_spoke_ns" neigh show 10.20.0.1 dev gre-ha |
			grep -q "lladdr $expected"; then
			return 0
		fi
		sleep 0.05
	done
	ip -n "$private_spoke_ns" neigh show 10.20.0.1 dev gre-ha >&2
	return 1
}

activate_spoke_member() {
	local member=$1 generation response

	generation=$(spoke_ha_show | grep -o '"generation":[0-9]*' | head -n 1 |
		cut -d: -f2)
	response=$(printf 'ha activate interface gre-ha protocol 10.20.0.1 member %s expect-generation %s\n' \
		"$member" "$generation" | nc -N -U "$runtime_dir/spoke.socket")
	grep -q '^Status: ok' <<<"$response"
}

for _ in {1..300}; do
	spoke_state=$(spoke_ha_show)
	if grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state" &&
		grep -q '"member":"hub-backup1".*"ready":true' <<<"$spoke_state" &&
		grep -q '"member":"hub-backup2".*"ready":true' <<<"$spoke_state"; then
		break
	fi
	sleep 0.05
done
spoke_state=$(spoke_ha_show)
printf '%s\n' "$spoke_state" >"$runtime_dir/spoke.ready.json"
grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state"
grep -q '"member":"hub-backup1".*"ready":true' <<<"$spoke_state"
grep -q '"member":"hub-backup2".*"ready":true' <<<"$spoke_state"
grep -q '"member":"hub-backup2".*"addresses":\["'"$hub3_configured_nbma"'","'"$hub3_underlay"'"\]' \
	<<<"$spoke_state"
grep -q '"member":"hub-primary".*"local_nbma":"'"$hub1_local_nbma"'".*"local_nbma_origin":"bootstrap"' \
	<<<"$spoke_state"
grep -q '"member":"hub-backup1".*"local_nbma":"'"$hub2_local_nbma"'".*"local_nbma_origin":"configured"' \
	<<<"$spoke_state"
grep -q '"member":"hub-backup2".*"local_nbma":null.*"local_nbma_origin":null' \
	<<<"$spoke_state"
wait_spoke_neighbor "$hub1_local_nbma"

log "validating disabled member is removed from the Spoke Hub List"
hub_list_generation=$(grep -o '"hub_list_generation":[0-9]*' \
	<<<"$spoke_state" | cut -d: -f2)
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha member disable hub-backup2 \
	>"$runtime_dir/member-disable-live.txt"
for _ in {1..200}; do
	spoke_state=$(spoke_ha_show)
	next_generation=$(grep -o '"hub_list_generation":[0-9]*' \
		<<<"$spoke_state" | cut -d: -f2)
	if ((next_generation > hub_list_generation)) &&
		grep -q '"member":"hub-backup2".*"state":"disabled"' \
			<<<"$spoke_state"; then
		break
	fi
	sleep 0.05
done
((next_generation > hub_list_generation))
grep -q '"active_member":"hub-primary"' <<<"$spoke_state"
grep -q '"member":"hub-backup2".*"state":"disabled"' <<<"$spoke_state"
invalid_before=$(grep -c 'Registration request has invalid HA member data' \
	"$runtime_dir/hub3.log" || true)
sleep 3
invalid_after=$(grep -c 'Registration request has invalid HA member data' \
	"$runtime_dir/hub3.log" || true)
[[ $invalid_after == "$invalid_before" ]]
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha member enable hub-backup2 \
	>"$runtime_dir/member-enable-live.txt"
for _ in {1..300}; do
	spoke_state=$(spoke_ha_show)
	if grep -q '"member":"hub-backup2".*"ready":true' \
		<<<"$spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-backup2".*"ready":true' <<<"$spoke_state"

log "validating purge preserves the managed HA bootstrap anchor"
purge_response=$("$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" \
	purge interface gre-ha protocol 10.20.0.1/32)
grep -q '^Status: ok' <<<"$purge_response"
grep -q '^Entries-Affected: 0' <<<"$purge_response"
wait_spoke_neighbor "$hub1_local_nbma"
spoke_state=$(spoke_ha_show)
grep -q '"active_member":"hub-primary"' <<<"$spoke_state"

for _ in {1..400}; do
	private_spoke_state=$(private_spoke_ha_show)
	if grep -q '"member":"hub-primary".*"selected_address":"'"$hub1_private_nbma"'".*"ready":true' \
		<<<"$private_spoke_state" &&
		grep -q '"member":"hub-backup1".*"selected_address":"'"$hub2_private_nbma"'".*"ready":true' \
			<<<"$private_spoke_state" &&
		grep -q '"active_member":"hub-primary"' <<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-primary".*"selected_address":"'"$hub1_private_nbma"'".*"ready":true' \
	<<<"$private_spoke_state"
grep -q '"member":"hub-backup1".*"selected_address":"'"$hub2_private_nbma"'".*"ready":true' \
	<<<"$private_spoke_state"
grep -q '"active_member":"hub-primary"' <<<"$private_spoke_state"
wait_private_spoke_neighbor "$hub1_private_nbma"
ip netns exec "$private_spoke_ns" ping -I 10.20.0.3 -c 3 -W 1 \
	198.18.20.1 >"$runtime_dir/private-spoke.initial-ping.txt"

log "validating endpoint failover within the Primary member"
ip -n "$private_spoke_ns" addr add 192.0.2.15/24 dev u-private
for _ in {1..200}; do
	private_spoke_state=$(private_spoke_ha_show)
	if grep -q '"member":"hub-primary".*"endpoint_reachable":\[true,true\].*"selected_address":"'"$hub1_private_nbma"'"' \
		<<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-primary".*"endpoint_reachable":\[true,true\].*"selected_address":"'"$hub1_private_nbma"'"' \
	<<<"$private_spoke_state"
ip -n "$hub1_ns" addr del "$hub1_private_nbma/24" dev u-hub1
for _ in {1..200}; do
	private_spoke_state=$(private_spoke_ha_show)
	if grep -q '"member":"hub-primary".*"selected_address":"'"$hub1_underlay"'".*"ready":true' \
		<<<"$private_spoke_state" &&
		grep -q '"active_member":"hub-primary"' <<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-primary".*"selected_address":"'"$hub1_underlay"'".*"ready":true' \
	<<<"$private_spoke_state"
grep -q '"active_member":"hub-primary"' <<<"$private_spoke_state"
wait_private_spoke_neighbor "$hub1_underlay"
ip -n "$hub1_ns" addr add "$hub1_private_nbma/24" dev u-hub1
for _ in {1..200}; do
	private_spoke_state=$(private_spoke_ha_show)
	if grep -q '"member":"hub-primary".*"selected_address":"'"$hub1_private_nbma"'".*"ready":true' \
		<<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-primary".*"selected_address":"'"$hub1_private_nbma"'".*"ready":true' \
	<<<"$private_spoke_state"
wait_private_spoke_neighbor "$hub1_private_nbma"

log "validating public and private Spoke endpoint selection"
spoke_ha_pid=$(pgrep -P "$spoke_pid" | head -n 1)
kill -STOP "$spoke_ha_pid"
activate_spoke_member hub-backup1
wait_spoke_neighbor "$hub2_local_nbma"
activate_spoke_member hub-backup2
wait_spoke_neighbor "$hub3_underlay"
activate_spoke_member hub-primary
wait_spoke_neighbor "$hub1_local_nbma"

log "validating local NBMA save, duplicate rejection and reload reconciliation"
"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" map save
grep -q "^  map 10.20.0.1/32 $hub1_underlay local-nbma $hub1_local_nbma register$" \
	"$runtime_dir/spoke.conf"
grep -q "^  ha-local-nbma hub-backup1 $hub2_local_nbma$" \
	"$runtime_dir/spoke.conf"
printf '  ha-local-nbma hub-backup1 %s\n' "$hub2_local_nbma" \
	>>"$runtime_dir/spoke.conf"
reload_response=$("$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" reload)
grep -q '^Status: failed' <<<"$reload_response"
sed -i '$d' "$runtime_dir/spoke.conf"
"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" reload
activate_spoke_member hub-backup1
wait_spoke_neighbor "$hub2_local_nbma"
sed -i '/^  ha-local-nbma hub-backup1 /d' "$runtime_dir/spoke.conf"
"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" reload
wait_spoke_neighbor "$hub2_underlay"
printf '  ha-local-nbma hub-backup1 %s\n' "$hub2_local_nbma" \
	>>"$runtime_dir/spoke.conf"
"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" reload
wait_spoke_neighbor "$hub2_local_nbma"
activate_spoke_member hub-primary
wait_spoke_neighbor "$hub1_local_nbma"
sed -i "s/local-nbma $hub1_local_nbma/local-nbma $hub1_reloaded_nbma/" \
	"$runtime_dir/spoke.conf"
"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" reload
wait_spoke_neighbor "$hub1_reloaded_nbma"
spoke_state=$(spoke_ha_show)
grep -q '"member":"hub-primary".*"local_nbma":"'"$hub1_reloaded_nbma"'".*"local_nbma_origin":"bootstrap"' \
	<<<"$spoke_state"
sed -i "s/local-nbma $hub1_reloaded_nbma/local-nbma $hub1_local_nbma/" \
	"$runtime_dir/spoke.conf"
"$bin_dir/opennhrpctl" -a "$runtime_dir/spoke.socket" reload
wait_spoke_neighbor "$hub1_local_nbma"
spoke_state=$(spoke_ha_show)
kill -CONT "$spoke_ha_pid"
old_spoke_ha_pid=$spoke_ha_pid
kill "$old_spoke_ha_pid"
for _ in {1..100}; do
	spoke_ha_pid=$(pgrep -P "$spoke_pid" | head -n 1 || true)
	if [[ -n $spoke_ha_pid && $spoke_ha_pid != "$old_spoke_ha_pid" ]]; then
		break
	fi
	sleep 0.05
done
[[ -n $spoke_ha_pid && $spoke_ha_pid != "$old_spoke_ha_pid" ]]

log "validating quiet steady-state registration refresh and HA probes"
probe_log_before=$(grep -hEc \
	'Received Resolution Request|Sending Resolution Reply' \
	"$runtime_dir"/hub?.log || true)
delete_log_before=$(grep -hEc 'Delete link from' \
	"$runtime_dir"/hub?.log || true)
sleep 31
if grep -q 'Peer registration failed: static entry exists' \
	"$runtime_dir"/hub?.log; then
	echo "HA registration refresh conflicted with a local route" >&2
	exit 1
fi
probe_log_after=$(grep -hEc \
	'Received Resolution Request|Sending Resolution Reply' \
	"$runtime_dir"/hub?.log || true)
delete_log_after=$(grep -hEc 'Delete link from' \
	"$runtime_dir"/hub?.log || true)
[[ $probe_log_after == "$probe_log_before" ]]
[[ $delete_log_after == "$delete_log_before" ]]
spoke_state=$(spoke_ha_show)
[[ $(grep -o '"state":"ready"' <<<"$spoke_state" | wc -l) -eq 3 ]]
grep -q '"active_member":"hub-primary"' <<<"$spoke_state"
wait_spoke_neighbor "$hub1_local_nbma"

log "validating simultaneous Standby reconnects"
hub2_old_ha_pid=$(pgrep -P "$hub2_pid" | head -n 1)
hub3_old_ha_pid=$(pgrep -P "$hub3_pid" | head -n 1)
kill "$hub2_old_ha_pid" "$hub3_old_ha_pid"
for _ in {1..200}; do
	hub2_new_ha_pid=$(pgrep -P "$hub2_pid" | head -n 1 || true)
	hub3_new_ha_pid=$(pgrep -P "$hub3_pid" | head -n 1 || true)
	if [[ -n $hub2_new_ha_pid && -n $hub3_new_ha_pid &&
		$hub2_new_ha_pid != "$hub2_old_ha_pid" &&
		$hub3_new_ha_pid != "$hub3_old_ha_pid" ]]; then
		break
	fi
	sleep 0.05
done
wait_coordinator hub2
wait_coordinator hub3
for _ in {1..200}; do
	cluster=$(cluster_json)
	if grep -q '"member":"hub-backup1".*"connected":true.*"authenticated":true' \
		<<<"$cluster" &&
		grep -q '"member":"hub-backup2".*"connected":true.*"authenticated":true' \
			<<<"$cluster"; then
		break
	fi
	sleep 0.05
done
cluster=$(cluster_json)
grep -q '"member":"hub-backup1".*"connected":true.*"authenticated":true' \
	<<<"$cluster"
grep -q '"member":"hub-backup2".*"connected":true.*"authenticated":true' \
	<<<"$cluster"

cluster_json_for() {
	local role=$1
	"$bin_dir/opennhrpctl" -a "$runtime_dir/$role-ha.socket" \
		ha cluster show --format json 2>/dev/null || true
}

log "validating adaptive Hub network health and takeover"
for _ in {1..400}; do
	hub1_cluster=$(cluster_json_for hub1)
	if grep -q '"network_health":"healthy"' <<<"$hub1_cluster" &&
		grep -q '"health_interval_seconds":10' <<<"$hub1_cluster"; then
		break
	fi
	sleep 0.1
done
grep -q '"health_interval_seconds":10' <<<"$hub1_cluster"
ip netns exec "$hub1_ns" iptables -I OUTPUT -p icmp --icmp-type echo-request \
	-d 198.51.100.250 -m comment --comment opennhrp-ha-health-test -j DROP
sleep 11
hub1_cluster=$(cluster_json_for hub1)
grep -q '"leader":"hub-primary"' <<<"$hub1_cluster"
grep -q '"network_health":"healthy"' <<<"$hub1_cluster"
ip netns exec "$hub1_ns" iptables -I OUTPUT -p icmp --icmp-type echo-request \
	-d 198.51.100.251 -m comment --comment opennhrp-ha-health-test -j DROP
for _ in {1..400}; do
	hub1_cluster=$(cluster_json_for hub1)
	hub2_cluster=$(cluster_json_for hub2)
	spoke_state=$(spoke_ha_show)
	if grep -q '"network_health":"unhealthy"' <<<"$hub1_cluster" &&
		grep -q '"service_available":false' <<<"$hub1_cluster" &&
		grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster" &&
		grep -q '"active_member":"hub-backup1"' <<<"$spoke_state"; then
		break
	fi
	sleep 0.1
done
grep -q '"network_health":"unhealthy"' <<<"$hub1_cluster"
grep -q '"health_interval_seconds":1' <<<"$hub1_cluster"
grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster"
grep -q '"active_member":"hub-backup1"' <<<"$spoke_state"
ip netns exec "$hub1_ns" iptables -D OUTPUT -p icmp --icmp-type echo-request \
	-d 198.51.100.251 -m comment --comment opennhrp-ha-health-test -j DROP
ip netns exec "$hub1_ns" iptables -D OUTPUT -p icmp --icmp-type echo-request \
	-d 198.51.100.250 -m comment --comment opennhrp-ha-health-test -j DROP
for _ in {1..300}; do
	hub1_cluster=$(cluster_json_for hub1)
	if grep -q '"network_health":"healthy"' <<<"$hub1_cluster" &&
		grep -q '"service_available":true' <<<"$hub1_cluster" &&
		grep -q '"isolated":false' <<<"$hub1_cluster"; then
		break
	fi
	sleep 0.1
done
grep -q '"network_health":"healthy"' <<<"$hub1_cluster"
grep -q '"leader":"hub-backup1"' <<<"$hub1_cluster"
"$bin_dir/opennhrpctl" -a "$runtime_dir/hub2-ha.socket" \
	ha failback request force >"$runtime_dir/health-failback.request.txt"
for _ in {1..200}; do
	hub1_cluster=$(cluster_json_for hub1)
	spoke_state=$(spoke_ha_show)
	if grep -q '"leader":"hub-primary"' <<<"$hub1_cluster" &&
		grep -q '"active_member":"hub-primary"' <<<"$spoke_state"; then
		break
	fi
	sleep 0.1
done
grep -q '"leader":"hub-primary"' <<<"$hub1_cluster"
if ! grep -q '"active_member":"hub-primary"' <<<"$spoke_state"; then
	printf 'Primary cluster after failback:\n%s\n' "$hub1_cluster" >&2
	printf 'Spoke HA after failback:\n%s\n' "$spoke_state" >&2
	ip -n "$spoke_ns" route get "$hub1_underlay" >&2 || true
	ip -n "$spoke_ns" route get "$hub1_private_nbma" >&2 || true
	ip -n "$spoke_ns" neigh show >&2 || true
	grep -E 'HA [Rr]egistration|no matching request|packet type [12]|candidate hub-primary' \
		"$runtime_dir/hub1.log" | tail -n 120 >&2 || true
	grep -E 'HA [Rr]egistration|no matching request|packet type [12]|candidate hub-primary' \
		"$runtime_dir/spoke.log" | tail -n 120 >&2 || true
	exit 1
fi

log "validating gre-ha down isolation, takeover, and recovered-node rejoin"
ip netns exec "$spoke_ns" ping -I 10.20.0.2 -c 5 -W 1 198.18.20.1 \
	>"$runtime_dir/ping.primary.txt"
ip -n "$hub1_ns" link set gre-ha down
for _ in {1..200}; do
	hub1_cluster=$(cluster_json_for hub1)
	hub2_cluster=$(cluster_json_for hub2)
	hub3_cluster=$(cluster_json_for hub3)
	spoke_state=$(spoke_ha_show)
	private_spoke_state=$(private_spoke_ha_show)
	if grep -q '"service_available":false' <<<"$hub1_cluster" &&
		grep -q '"isolated":true' <<<"$hub1_cluster" &&
		grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster" &&
		grep -q '"leader":"hub-backup1"' <<<"$hub3_cluster" &&
		grep -q '"member":"hub-backup1".*"connected":true' \
			<<<"$hub3_cluster" &&
		grep -q '"active_member":"hub-backup1"' <<<"$spoke_state" &&
		grep -q '"active_member":"hub-backup1"' \
			<<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
hub1_cluster=$(cluster_json_for hub1)
hub2_cluster=$(cluster_json_for hub2)
hub3_cluster=$(cluster_json_for hub3)
spoke_state=$(spoke_ha_show)
private_spoke_state=$(private_spoke_ha_show)
grep -q '"service_available":false' <<<"$hub1_cluster"
grep -q '"isolated":true' <<<"$hub1_cluster"
grep -q '"leader":"hub-backup1"' <<<"$hub2_cluster"
grep -q '"leader":"hub-backup1"' <<<"$hub3_cluster"
grep -q '"member":"hub-backup1".*"connected":true' <<<"$hub3_cluster"
grep -q '"active_member":"hub-backup1"' <<<"$spoke_state"
grep -q '"member":"hub-backup1".*"selected_address":"'"$hub2_private_nbma"'".*"ready":true' \
	<<<"$private_spoke_state"
grep -q '"active_member":"hub-backup1"' <<<"$private_spoke_state"
wait_private_spoke_neighbor "$hub2_private_nbma"
ip netns exec "$spoke_ns" ping -I 10.20.0.2 -c 5 -W 1 198.18.20.1 \
	>"$runtime_dir/ping.backup.txt"
ip netns exec "$private_spoke_ns" ping -I 10.20.0.3 -c 5 -W 1 \
	198.18.20.1 >"$runtime_dir/private-spoke.backup.txt"

ip -n "$hub1_ns" link set gre-ha up
for _ in {1..200}; do
	hub1_cluster=$(cluster_json_for hub1)
	if grep -q '"leader":"hub-backup1"' <<<"$hub1_cluster" &&
		grep -q '"service_available":true' <<<"$hub1_cluster" &&
		grep -q '"isolated":false' <<<"$hub1_cluster" &&
		grep -q '"member":"hub-backup1".*"connected":true' \
			<<<"$hub1_cluster"; then
		break
	fi
	sleep 0.05
done
hub1_cluster=$(cluster_json_for hub1)
grep -q '"leader":"hub-backup1"' <<<"$hub1_cluster"
grep -q '"service_available":true' <<<"$hub1_cluster"
grep -q '"isolated":false' <<<"$hub1_cluster"
grep -q '"member":"hub-backup1".*"connected":true' <<<"$hub1_cluster"
spoke_state=$(spoke_ha_show)
grep -q '"active_member":"hub-backup1"' <<<"$spoke_state"
private_spoke_state=$(private_spoke_ha_show)
grep -q '"active_member":"hub-backup1"' <<<"$private_spoke_state"
for _ in {1..400}; do
	spoke_state=$(spoke_ha_show)
	if grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state"

log "validating one-shot bootstrap purge while Primary is a Standby"
purge_before=$(grep -c \
	'Received Purge Request from proto src 10.20.0.2 to 10.20.0.1' \
	"$runtime_dir/hub1.log" || true)
no_peer_before=$(grep -c \
	'No peer entry for protocol address 10.20.0.2' \
	"$runtime_dir/hub1.log" || true)
stop_pid "$spoke_pid"
spoke_pid=
rm -f -- "$runtime_dir/spoke.socket" "$runtime_dir/spoke.pid"
start_core spoke "$spoke_ns" "$runtime_dir/spoke-state" \
	"$runtime_dir/spoke.conf"
for _ in {1..300}; do
	spoke_state=$(spoke_ha_show)
	if grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state" &&
		grep -q '"member":"hub-backup1".*"ready":true' <<<"$spoke_state" &&
		grep -q '"active_member":"hub-backup1"' <<<"$spoke_state"; then
		break
	fi
	sleep 0.05
done
if ! grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state"; then
	printf 'Spoke bootstrap state:\n%s\n' "$spoke_state" >&2
	grep -E 'HA Registration|HA (authentication|metadata)|no matching request|packet type [12]' \
		"$runtime_dir/hub1.log" | tail -n 120 >&2 || true
	grep -E 'HA Registration|HA (authentication|metadata)|no matching request|packet type [12]' \
		"$runtime_dir/spoke.log" | tail -n 120 >&2 || true
	exit 1
fi
grep -q '"member":"hub-backup1".*"ready":true' <<<"$spoke_state"
grep -q '"active_member":"hub-backup1"' <<<"$spoke_state"
sleep 31
purge_after=$(grep -c \
	'Received Purge Request from proto src 10.20.0.2 to 10.20.0.1' \
	"$runtime_dir/hub1.log" || true)
no_peer_after=$(grep -c \
	'No peer entry for protocol address 10.20.0.2' \
	"$runtime_dir/hub1.log" || true)
[[ $((purge_after - purge_before)) -eq 1 ]]
[[ $no_peer_after -eq $no_peer_before ]]

log "validating safe failback state and authenticated transfer"
for _ in {1..400}; do
	failback_state=$("$bin_dir/opennhrpctl" \
		-a "$runtime_dir/hub2-ha.socket" ha failback show --format json)
	if grep -q '"primary_healthy":true' <<<"$failback_state" &&
		grep -q '"primary_synchronized":true' <<<"$failback_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"mode":"automatic"' <<<"$failback_state"
grep -q '"local_backup_leader":true' <<<"$failback_state"
grep -q '"primary_healthy":true' <<<"$failback_state"
grep -q '"primary_synchronized":true' <<<"$failback_state"
for _ in {1..400}; do
	spoke_state=$(spoke_ha_show)
	private_spoke_state=$(private_spoke_ha_show)
	if grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state" &&
		grep -q '"member":"hub-primary".*"ready":true' \
			<<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
grep -q '"member":"hub-primary".*"ready":true' <<<"$spoke_state"
grep -q '"member":"hub-primary".*"ready":true' <<<"$private_spoke_state"
hub1_failback_delete_before=$(grep -c 'Delete link from' \
	"$runtime_dir/hub1.log" || true)
"$bin_dir/opennhrpctl" -a "$runtime_dir/hub2-ha.socket" \
	ha failback request force >"$runtime_dir/failback.request.txt"
grep -q 'Requested: force' "$runtime_dir/failback.request.txt"
for _ in {1..400}; do
	hub1_cluster=$(cluster_json_for hub1)
	hub2_cluster=$(cluster_json_for hub2)
	spoke_state=$(spoke_ha_show)
	private_spoke_state=$(private_spoke_ha_show)
	if grep -q '"leader":"hub-primary"' <<<"$hub1_cluster" &&
		grep -q '"leader":"hub-primary"' <<<"$hub2_cluster" &&
		grep -q '"active_member":"hub-primary"' <<<"$spoke_state" &&
		grep -q '"active_member":"hub-primary"' \
			<<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
if ! grep -q '"leader":"hub-primary"' <<<"$hub1_cluster" ||
	! grep -q '"leader":"hub-primary"' <<<"$hub2_cluster" ||
	! grep -q '"active_member":"hub-primary"' <<<"$spoke_state" ||
	! grep -q '"active_member":"hub-primary"' <<<"$private_spoke_state"; then
	printf 'Primary cluster:\n%s\nBackup cluster:\n%s\n' \
		"$hub1_cluster" "$hub2_cluster" >&2
	printf 'Spoke:\n%s\nPrivate Spoke:\n%s\n' \
		"$spoke_state" "$private_spoke_state" >&2
	exit 1
fi
grep -q '"leader":"hub-primary"' <<<"$hub1_cluster"
grep -q '"leader":"hub-primary"' <<<"$hub2_cluster"
grep -q '"active_member":"hub-primary"' <<<"$spoke_state"
grep -q '"active_member":"hub-primary"' <<<"$private_spoke_state"
hub1_failback_delete_after=$(grep -c 'Delete link from' \
	"$runtime_dir/hub1.log" || true)
[[ $hub1_failback_delete_after == "$hub1_failback_delete_before" ]]
grep -q '"member":"hub-primary".*"selected_address":"'"$hub1_private_nbma"'".*"ready":true' \
	<<<"$private_spoke_state"
wait_private_spoke_neighbor "$hub1_private_nbma"
ip netns exec "$spoke_ns" ping -I 10.20.0.2 -c 5 -W 1 198.18.20.1 \
	>"$runtime_dir/ping.failback.txt"
ip netns exec "$private_spoke_ns" ping -I 10.20.0.3 -c 5 -W 1 \
	198.18.20.1 >"$runtime_dir/private-spoke.failback.txt"

invite_id=$(OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha invite list | \
	awk '$2 == "hub-backup1" { print $1 }')
[[ ${#invite_id} -eq 12 ]]
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha invite delete --id-prefix "$invite_id" \
	>"$runtime_dir/delete-claimed-invite.txt"
! OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha invite list | grep -q 'hub-backup1'
OPENNHRP_HA_STATE_DIR="$runtime_dir/hub1-state" \
	"$bin_dir/opennhrpctl" ha members show | grep -q 'hub-backup1'
unset invite_id

log "validating three-Hub majority fences a one-Hub Leader partition"
for role in hub1 hub2 hub3; do
	cluster=$(hub_cluster "$role")
	grep -q '"policy":"hub-majority"' <<<"$cluster"
	grep -q '"voters":3,"required":2' <<<"$cluster"
done
ip netns exec "$hub1_ns" iptables -I INPUT -p tcp --dport 49002 \
	-m comment --comment opennhrp-ha-majority-test -j DROP
ip netns exec "$hub1_ns" iptables -I OUTPUT -p tcp --dport 49002 \
	-m comment --comment opennhrp-ha-majority-test -j DROP
for _ in {1..300}; do
	roles="$(hub_core_role hub1) $(hub_core_role hub2) $(hub_core_role hub3)"
	if [[ $(grep -o 'leader' <<<"$roles" | wc -l) -gt 1 ]]; then
		echo "multiple serviceable Leaders during Hub-majority partition: $roles" >&2
		exit 1
	fi
	spoke_state=$(spoke_ha_show)
	private_spoke_state=$(private_spoke_ha_show)
	if [[ $(hub_core_role hub1) == standby &&
		$(hub_core_role hub2) == leader &&
		$(hub_core_role hub3) == standby ]] &&
		grep -q '"active_member":"hub-backup1"' <<<"$spoke_state" &&
		grep -q '"active_member":"hub-backup1"' \
			<<<"$private_spoke_state"; then
		break
	fi
	sleep 0.05
done
[[ $(hub_core_role hub1) == standby ]]
[[ $(hub_core_role hub2) == leader ]]
[[ $(hub_core_role hub3) == standby ]]
grep -q '"quorum_available":false' <<<"$(hub_cluster hub1)"
grep -q '"active_member":"hub-backup1"' <<<"$spoke_state"
grep -q '"active_member":"hub-backup1"' <<<"$private_spoke_state"
ip netns exec "$spoke_ns" ping -I 10.20.0.2 -c 2 -W 1 198.18.20.1 \
	>"$runtime_dir/ping.majority.txt"
ip netns exec "$hub1_ns" iptables -D INPUT -p tcp --dport 49002 \
	-m comment --comment opennhrp-ha-majority-test -j DROP
ip netns exec "$hub1_ns" iptables -D OUTPUT -p tcp --dport 49002 \
	-m comment --comment opennhrp-ha-majority-test -j DROP
for _ in {1..300}; do
	hub1_cluster=$(hub_cluster hub1)
	if grep -q '"leader":"hub-backup1"' <<<"$hub1_cluster" &&
		grep -q '"quorum_available":true' <<<"$hub1_cluster"; then
		break
	fi
	sleep 0.05
done
grep -q '"leader":"hub-backup1"' <<<"$hub1_cluster"
grep -q '"quorum_available":true' <<<"$hub1_cluster"

stop_pid "$spoke_pid"
spoke_pid=
stop_pid "$private_spoke_pid"
private_spoke_pid=
! grep -q 'invalid peer type' "$runtime_dir/spoke.log"
if grep -q 'Reloading configuration file' "$runtime_dir/hub1.log" \
  "$runtime_dir/hub3.log" ||
  [[ $(grep -c 'Reloading configuration file' "$runtime_dir/hub2.log") -ne 1 ]]; then
	echo "managed Hub synchronization triggered a full config reload" >&2
	exit 1
fi
grep -q 'Reloading managed HA state' "$runtime_dir"/hub?.log

log "managed Invite, three-Hub reconnect, gre-ha isolation and takeover passed"
