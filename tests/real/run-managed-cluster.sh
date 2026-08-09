#!/usr/bin/env bash

set -euo pipefail

archive=${1:?usage: run-managed-cluster.sh /path/to/opennhrp-ha-test-BUILD.tar.gz}
primary_host=${PRIMARY_HOST:-150.158.214.148}
backup_host=${BACKUP_HOST:-49.234.145.47}
spoke_host=${SPOKE_HOST:-121.5.232.164}
rounds=${ROUNDS:-30}
fault_mode=${FAULT_MODE:-coordinator}
health_targets=(119.29.29.29 223.5.5.5)
health_comment=opennhrp-ha-health-test
archive_name=$(basename "$archive")
build_id=${archive_name#opennhrp-ha-test-}
build_id=${build_id%.tar.gz}
remote_base="/tmp/opennhrp-ha-test/$build_id"
remote_archive="/tmp/$archive_name"
test_interface=gre-ht
result_dir=$(mktemp -d /tmp/opennhrp-ha-managed-real.XXXXXX)
ssh_control="$result_dir/ssh-%C"
ssh_options=(-o BatchMode=yes -o ConnectTimeout=8 -o ControlMaster=auto
	-o ControlPersist=60 -o "ControlPath=$ssh_control")
deployed=0
system_services_stopped=0

log() {
	printf '[%s] %s\n' "$(date +%H:%M:%S.%3N)" "$*"
}

remote() {
	local host=$1
	shift
	ssh "${ssh_options[@]}" "root@$host" "$@"
}

stop_processes() {
	local host=$1
	remote "$host" \
		"for pid in '$remote_base/run/opennhrp-ha.pid' '$remote_base/run/opennhrp.pid'; do if test -s \"\$pid\"; then kill \"\$(cat \"\$pid\")\" 2>/dev/null || true; fi; done" \
		2>/dev/null || true
}

health_fault_down() {
	local host=$1 target
	for target in "${health_targets[@]}"; do
		remote "$host" "iptables -C OUTPUT -p icmp --icmp-type echo-request -d '$target' -m comment --comment '$health_comment' -j DROP 2>/dev/null || iptables -I OUTPUT -p icmp --icmp-type echo-request -d '$target' -m comment --comment '$health_comment' -j DROP"
	done
}

health_fault_up() {
	local host=$1 target
	for target in "${health_targets[@]}"; do
		remote "$host" "while iptables -C OUTPUT -p icmp --icmp-type echo-request -d '$target' -m comment --comment '$health_comment' -j DROP 2>/dev/null; do iptables -D OUTPUT -p icmp --icmp-type echo-request -d '$target' -m comment --comment '$health_comment' -j DROP; done" \
			2>/dev/null || true
	done
}

cleanup() {
	status=$?
	set +e
	if ((deployed)); then
		if ((status != 0)); then
			for role_host in "primary:$primary_host" "backup:$backup_host" \
				"spoke:$spoke_host"; do
				role=${role_host%%:*}
				host=${role_host#*:}
				remote "$host" \
					"echo '== processes =='; ps -ef | grep '$remote_base/bin/opennhrp' | grep -v grep || true; echo '== sockets =='; ss -tnp | grep ':49002' || true; echo '== coordinator log =='; tail -n 200 '$remote_base/run/opennhrp-ha.log' 2>/dev/null || true; echo '== core log =='; tail -n 100 '$remote_base/run/opennhrp.log' 2>/dev/null || true; echo '== cluster =='; '$remote_base/bin/opennhrpctl' -a '$remote_base/run/opennhrp-ha.socket' ha cluster show --format json 2>/dev/null || true; echo '== replication =='; '$remote_base/bin/opennhrpctl' -a '$remote_base/run/opennhrp-ha.socket' ha replication show --format json 2>/dev/null || true" \
					>"$result_dir/$role.failure.txt" 2>&1 || true
			done
			log "failure diagnostics saved in $result_dir"
		fi
		stop_processes "$spoke_host"
		stop_processes "$backup_host"
		stop_processes "$primary_host"
		remote "$spoke_host" \
			"ip rule del priority 10221 2>/dev/null || true; ip route flush table 221 2>/dev/null || true" \
			2>/dev/null || true
		for host in "$primary_host" "$backup_host"; do
			health_fault_up "$host"
			remote "$host" "ip addr del 198.18.21.1/32 dev lo 2>/dev/null || true" \
				2>/dev/null || true
		done
		for host in "$primary_host" "$backup_host" "$spoke_host"; do
			remote "$host" \
				"ip link del '$test_interface' 2>/dev/null || true; if test \"\$(readlink /tmp/opennhrp-ha-current 2>/dev/null)\" = '$remote_base'; then unlink /tmp/opennhrp-ha-current; fi; rm -rf -- '$remote_base'; rm -f -- '$remote_archive'" \
				2>/dev/null || true
		done
	fi
	if ((system_services_stopped)); then
		for host in "$primary_host" "$backup_host" "$spoke_host"; do
			remote "$host" "systemctl start opennhrp.service" 2>/dev/null || true
		done
		for host in "$primary_host" "$backup_host" "$spoke_host"; do
			remote "$host" "for i in \$(seq 1 100); do systemctl is-active --quiet opennhrp.service && exit 0; sleep 0.1; done; exit 1" \
				2>/dev/null || status=1
		done
	fi
	for host in "$primary_host" "$backup_host" "$spoke_host"; do
		ssh "${ssh_options[@]}" -O exit "root@$host" 2>/dev/null || true
	done
	rm -f -- "$result_dir/keys"
	if ((status == 0)); then
		rm -rf -- "$result_dir"
	fi
	return "$status"
}
trap cleanup EXIT HUP INT TERM

for tool in ssh scp awk sort; do
	command -v "$tool" >/dev/null
done
[[ -f $archive && -f $archive.sha256 ]]
(cd "$(dirname "$archive")" && sha256sum -c "$(basename "$archive").sha256")

log "stopping system OpenNHRP services for isolated real-host testing"
remote "$spoke_host" "systemctl stop opennhrp.service"
remote "$backup_host" "systemctl stop opennhrp.service"
remote "$primary_host" "systemctl stop opennhrp.service"
system_services_stopped=1

log "deploying managed HA bundle $build_id"
for host in "$primary_host" "$backup_host" "$spoke_host"; do
	scp -q "${ssh_options[@]}" "$archive" "root@$host:$remote_archive"
	remote "$host" \
		"test ! -e /tmp/opennhrp-ha-current; mkdir -p '$remote_base/run'; tar -C /tmp/opennhrp-ha-test -xzf '$remote_archive'; cd '$remote_base'; sha256sum -c SHA256SUMS; ln -s '$remote_base' /tmp/opennhrp-ha-current; mkdir -m 0700 '$remote_base/run/ha'"
done
deployed=1

ensure_mgre() {
	local host=$1 address=$2
	remote "$host" \
		"test ! -e /sys/class/net/$test_interface; ip tunnel add '$test_interface' mode gre key 1021 ttl 64; ip link set '$test_interface' mtu 1400 up; ip addr add '$address/24' dev '$test_interface'"
}

ensure_mgre "$primary_host" 10.21.0.1
ensure_mgre "$backup_host" 10.21.0.1
ensure_mgre "$spoke_host" 10.21.0.2

remote "$primary_host" \
	"OPENNHRP_HA_STATE_DIR='$remote_base/run/ha' '$remote_base/bin/opennhrpctl' ha cluster init --interface '$test_interface' --member-id hub-primary --advertise-address '$primary_host' --format json >'$remote_base/run/init.json'"

start_core() {
	local host=$1 config=$2
	remote "$host" \
		"pid='$remote_base/run/opennhrp.pid'; if test -s \"\$pid\" && kill -0 \"\$(cat \"\$pid\")\" 2>/dev/null; then exit 0; fi; nohup env OPENNHRP_HA_STATE_DIR='$remote_base/run/ha' '$remote_base/bin/opennhrp' -a '$remote_base/run/opennhrp.socket' -H '$remote_base/run/ha' -c '$remote_base/config/$config' -s /bin/true -p \"\$pid\" -v >>'$remote_base/run/opennhrp.log' 2>&1 </dev/null & for i in \$(seq 1 100); do test -S '$remote_base/run/opennhrp.socket' && exit 0; sleep 0.05; done; exit 1"
}

wait_hub() {
	local host=$1
	remote "$host" \
		"socket='$remote_base/run/opennhrp-ha.socket'; for i in \$(seq 1 100); do if test -S \"\$socket\" && '$remote_base/bin/opennhrpctl' -a \"\$socket\" ha cluster show --format json >/dev/null 2>&1; then exit 0; fi; sleep 0.05; done; exit 1"
}

stop_hub() {
	local host=$1
	remote "$host" \
		"parent=\$(cat '$remote_base/run/opennhrp.pid'); pid=\$(pgrep -P \"\$parent\" | head -n 1); test -n \"\$pid\"; kill \"\$pid\"; for i in \$(seq 1 100); do if ! kill -0 \"\$pid\" 2>/dev/null; then exit 0; fi; sleep 0.05; done; exit 1"
}

start_core "$primary_host" hub-primary.conf
wait_hub "$primary_host"

log "creating Invite and enrolling Backup without peer configuration"
invite=$(remote "$primary_host" \
	"OPENNHRP_HA_STATE_DIR='$remote_base/run/ha' '$remote_base/bin/opennhrpctl' ha invite create --member-id hub-backup1 --format plain")
printf '%s\n' "$invite" | ssh -T "${ssh_options[@]}" "root@$backup_host" \
	"OPENNHRP_HA_STATE_DIR='$remote_base/run/ha' '$remote_base/bin/opennhrpctl' ha join --interface '$test_interface' --advertise-address '$backup_host'"
unset invite
start_core "$backup_host" hub-backup1.conf
wait_hub "$backup_host"

for host in "$primary_host" "$backup_host"; do
	for target in "${health_targets[@]}"; do
		remote "$host" "ping -c 3 -W 1 '$target' >/dev/null"
	done
done

# No keyring scp needed for Spoke in no-keyring HA mode
start_core "$spoke_host" spoke.conf

for host in "$primary_host" "$backup_host"; do
	remote "$host" "ip -4 addr show dev lo | grep -q '198.18.21.1/32' || ip addr add 198.18.21.1/32 dev lo"
done
remote "$spoke_host" \
	"ip route add 10.21.0.0/24 dev '$test_interface' scope link table 221; ip route add default via 10.21.0.1 dev '$test_interface' table 221; ip rule add priority 10221 from 10.21.0.2/32 lookup 221"

ha_show() {
	remote "$spoke_host" \
		"'$remote_base/bin/opennhrpctl' -a '$remote_base/run/opennhrp.socket' ha show interface '$test_interface' format json" 2>/dev/null || true
}

active_member() {
	ha_show | sed -n 's/.*"active_member":\("[^"]*"\|null\).*/\1/p' | tr -d '"'
}

wait_active() {
	local expected=$1 timeout_ms=${2:-7000}
	local start now
	start=$(date +%s%3N)
	while [[ $(active_member) != "$expected" ]]; do
		now=$(date +%s%3N)
		if ((now - start >= timeout_ms)); then
			ha_show >&2
			return 1
		fi
		sleep 0.1
	done
}

wait_hub_rejoined() {
	local host=$1 expected_leader=$2 timeout_ms=${3:-10000}
	local start now state
	start=$(date +%s%3N)
	while true; do
		state=$(remote "$host" \
			"'$remote_base/bin/opennhrpctl' -a '$remote_base/run/opennhrp-ha.socket' ha cluster show --format json" \
			2>/dev/null || true)
		if grep -q '"leader":"'"$expected_leader"'"' <<<"$state" &&
			grep -q '"isolated":false' <<<"$state" &&
			grep -q '"connected":true,"authenticated":true' <<<"$state"; then
			return 0
		fi
		now=$(date +%s%3N)
		if ((now - start >= timeout_ms)); then
			printf '%s\n' "$state" >&2
			return 1
		fi
		sleep 0.1
	done
}

for _ in {1..200}; do
	state=$(remote "$primary_host" \
		"'$remote_base/bin/opennhrpctl' -a '$remote_base/run/opennhrp-ha.socket' ha cluster show --format json" 2>/dev/null || true)
	grep -q '"member":"hub-backup1".*"state":"active"' <<<"$state" && break
	sleep 0.1
done
grep -q '"member":"hub-backup1".*"state":"active"' <<<"$state"
wait_active hub-primary 20000
remote "$spoke_host" "ping -I 10.21.0.2 -c 5 -W 1 198.18.21.1" \
	>"$result_dir/ping.initial"

case $fault_mode in
coordinator | gre-down | health) ;;
*)
	echo "unsupported FAULT_MODE: $fault_mode" >&2
	exit 1
	;;
esac
log "running $rounds alternating $fault_mode failures"
: >"$result_dir/recovery-ms"
active=hub-primary
for ((round = 1; round <= rounds; round++)); do
	if [[ $active == hub-primary ]]; then
		failed_host=$primary_host
		expected=hub-backup1
	else
		failed_host=$backup_host
		expected=hub-primary
	fi
	start=$(date +%s%3N)
	case $fault_mode in
	coordinator) stop_hub "$failed_host" ;;
	gre-down) remote "$failed_host" "ip link set '$test_interface' down" ;;
	health) health_fault_down "$failed_host" ;;
	esac
	if [[ $fault_mode == health ]]; then
		wait_active "$expected" 15000
	else
		wait_active "$expected" 7000
	fi
	remote "$spoke_host" "ping -I 10.21.0.2 -c 1 -W 2 198.18.21.1" >/dev/null
	end=$(date +%s%3N)
	printf '%d\n' "$((end - start))" >>"$result_dir/recovery-ms"
	case $fault_mode in
	coordinator) wait_hub "$failed_host" ;;
	gre-down) remote "$failed_host" "ip link set '$test_interface' up" ;;
	health) health_fault_up "$failed_host" ;;
	esac
	if [[ $fault_mode == health ]]; then
		wait_hub_rejoined "$failed_host" "$expected" 30000
	else
		wait_hub_rejoined "$failed_host" "$expected"
	fi
	active=$expected
done

sort -n "$result_dir/recovery-ms" >"$result_dir/recovery.sorted"
count=$(wc -l <"$result_dir/recovery.sorted")
p95_index=$(((count * 95 + 99) / 100))
p95=$(sed -n "${p95_index}p" "$result_dir/recovery.sorted")
printf 'fault=%s rounds=%d p95_ms=%d\n' "$fault_mode" "$count" "$p95" |
	tee "$result_dir/summary.txt"
if [[ $fault_mode == health ]]; then
	((p95 < 15000))
	log "validating one complete automatic failback to Primary"
	if [[ $active == hub-primary ]]; then
		health_fault_down "$primary_host"
		wait_active hub-backup1 15000
		health_fault_up "$primary_host"
		wait_hub_rejoined "$primary_host" hub-backup1 30000
	fi
	start=$(date +%s%3N)
	wait_active hub-primary 450000
	end=$(date +%s%3N)
	printf 'automatic_failback_ms=%d\n' "$((end - start))" |
		tee -a "$result_dir/summary.txt"
	remote "$spoke_host" "ping -I 10.21.0.2 -c 3 -W 2 198.18.21.1" \
		>/dev/null
else
	((p95 < 2000))
fi

for host in "$primary_host" "$backup_host"; do
	remote "$host" "ip -d link show '$test_interface'; ip -4 addr show dev '$test_interface'"
done >"$result_dir/hubs.gre.txt"
remote "$spoke_host" "ip -d link show '$test_interface'; ip -4 addr show dev '$test_interface'; ip route show table main; ip route show table 221; ip neigh show dev '$test_interface'" \
	>"$result_dir/spoke.final.txt"
log "managed real-environment HA validation passed"
