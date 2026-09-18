#!/usr/bin/env python3
"""sudo python3 tests/netns/test-peer-cache.py (after make compile)."""
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.check_output([str(arg) for arg in args], stderr=subprocess.STDOUT, text=True)


def main():
    assert os.geteuid() == 0, "run as root"
    prefix = f"onhrp-cache-{os.getpid()}"
    namespaces = []
    processes = {}

    with tempfile.TemporaryDirectory(prefix="opennhrp-cache-") as directory:
        work = Path(directory)

        def ns(node, *args):
            return run("ip", "netns", "exec", f"{prefix}-{node}", *args)

        def eventually(check, timeout=10):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    if check():
                        return
                except (OSError, subprocess.CalledProcessError):
                    pass
                time.sleep(.1)
            raise AssertionError("condition timed out")

        def ctl(node):
            output = run(REPO / "nhrp/opennhrpctl", "-a", work / f"{node}.sock", "show")
            assert "Status: failed" not in output, output
            return output

        def start(node):
            socket_path = work / f"{node}.sock"
            socket_path.unlink(missing_ok=True)
            log = (work / f"{node}.log").open("a")
            process = subprocess.Popen(
                ["ip", "netns", "exec", f"{prefix}-{node}", str(REPO / "nhrp/opennhrp"),
                 "-a", str(socket_path), "-H", str(work / f"{node}-state"),
                 "-c", str(work / f"{node}.conf"), "-s", str(work / "script"),
                 "-p", str(work / f"{node}.pid"), "-v"],
                stdout=log, stderr=log, start_new_session=True)
            log.close()
            processes[node] = process
            eventually(lambda: process.poll() is None and socket_path.exists() and bool(ctl(node)))

        def stop(node):
            process = processes.pop(node)
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
            assert process.returncode == 0, f"{node} exited {process.returncode}"

        def has_peer(node, peer_type, address):
            pattern = rf"Type: {re.escape(peer_type)}\nProtocol-Address: {re.escape(address)}/"
            return re.search(pattern, ctl(node)) is not None

        try:
            for node in ("h", "s1", "s2"):
                namespace = f"{prefix}-{node}"
                run("ip", "netns", "add", namespace)
                namespaces.append(namespace)
                ns(node, "ip", "link", "set", "lo", "up")

            ns("h", "ip", "link", "add", "br0", "type", "bridge")
            ns("h", "ip", "link", "set", "br0", "up")
            ns("h", "ip", "addr", "add", "192.0.2.1/24", "dev", "br0")
            for node, address in (("s1", "192.0.2.13"), ("s2", "192.0.2.14")):
                ns("h", "ip", "link", "add", f"{node}-link", "type", "veth",
                   "peer", "name", "uplink", "netns", f"{prefix}-{node}")
                ns("h", "ip", "link", "set", f"{node}-link", "master", "br0")
                ns("h", "ip", "link", "set", f"{node}-link", "up")
                ns(node, "ip", "link", "set", "uplink", "up")
                ns(node, "ip", "addr", "add", f"{address}/24", "dev", "uplink")

            for node, address, underlay in (("h", "10.20.0.1", "192.0.2.1"),
                                            ("s1", "10.20.0.2", "192.0.2.13"),
                                            ("s2", "10.20.0.3", "192.0.2.14")):
                ns(node, "ip", "tunnel", "add", "gre-cache", "mode", "gre",
                   "local", underlay, "key", "1020", "ttl", "64")
                ns(node, "ip", "link", "set", "gre-cache", "mtu", "1400", "up")
                ns(node, "ip", "addr", "add", f"{address}/24", "dev", "gre-cache")
                ns(node, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0",
                   "net.ipv4.conf.gre-cache.rp_filter=0")
                (work / f"{node}-state").mkdir(mode=0o700)
            ns("h", "sysctl", "-qw", "net.ipv4.ip_forward=1")
            ns("s2", "ip", "link", "add", "lan", "type", "dummy")
            ns("s2", "ip", "link", "set", "lan", "up")
            ns("s2", "ip", "addr", "add", "172.16.2.1/24", "dev", "lan")

            events = work / "events.log"
            script = work / "script"
            script.write_text(
                "#!/bin/sh\n"
                f"echo \"$1 $NHRP_TYPE $NHRP_DESTADDR/$NHRP_DESTPREFIX\" >> {events}\n"
                "case $1 in\n"
                "route-up) ip route replace \"$NHRP_DESTADDR/$NHRP_DESTPREFIX\" "
                "proto 42 via \"$NHRP_NEXTHOP\" dev \"$NHRP_INTERFACE\";;\n"
                "route-down) ip route del \"$NHRP_DESTADDR/$NHRP_DESTPREFIX\" "
                "proto 42 2>/dev/null || true;;\n"
                "esac\n"
                "exit 0\n")
            script.chmod(0o755)

            (work / "h.conf").write_text(
                "interface gre-cache\n"
                "  holding-time 60\n"
                "  redirect\n"
                "  enable-ha member-id h advertise 192.0.2.1\n")
            for node in ("s1", "s2"):
                (work / f"{node}.conf").write_text(
                    "interface gre-cache\n"
                    "  holding-time 60\n"
                    "  route-table 100\n"
                    "  map 10.20.0.1/24 192.0.2.1 register\n"
                    "  shortcut\n")

            # Hub: a legacy registration is saved, an HA-capable one is not.
            start("h")
            ns("s1", sys.executable, REPO / "tests/netns/test-legacy-spoke.py",
               "--send", "192.0.2.1", "legacy", "10.20.0.2")
            ns("s1", sys.executable, REPO / "tests/netns/test-legacy-spoke.py",
               "--send", "192.0.2.1", "ha", "10.20.0.99")
            eventually(lambda: has_peer("h", "dynamic", "10.20.0.2"))
            stop("h")
            state = work / "h-state/peer-cache.state"
            snapshot = state.read_text()
            assert snapshot.startswith("OPENNHRP-PEER-CACHE 1\n")
            assert "dynamic gre-cache 10.20.0.2/32 192.0.2.13" in snapshot
            assert "10.20.0.99" not in snapshot
            assert stat.S_IMODE(state.stat().st_mode) == 0o600

            start("h")
            eventually(lambda: has_peer("h", "dynamic", "10.20.0.2"))
            assert not has_peer("h", "dynamic", "10.20.0.99")
            assert not state.exists(), "loaded Hub snapshot was not consumed"
            ns("s1", "ip", "neigh", "replace", "10.20.0.1", "lladdr", "192.0.2.1",
               "nud", "permanent", "dev", "gre-cache")
            ns("h", "ping", "-c", "1", "-W", "2", "-I", "10.20.0.1", "10.20.0.2")
            stop("h")

            # Spoke: load learned peer forms, then save and restore them again.
            start("h")
            start("s1")
            start("s2")
            eventually(lambda: has_peer("h", "dynamic", "10.20.0.3"))
            stop("s1")
            state = work / "s1-state/peer-cache.state"
            expires = int(time.time()) + 60
            state.write_text(
                "OPENNHRP-PEER-CACHE 1\n"
                f"cached gre-cache 10.20.0.3/32 192.0.2.14 - 1400 {expires}\n"
                f"shortcut-route gre-cache 172.16.2.0/24 10.20.0.3 - 0 {expires}\n")
            state.chmod(0o600)
            before = events.read_text().count("route-up shortcut-route 172.16.2.0/24")
            start("s1")
            eventually(lambda: has_peer("s1", "cached", "10.20.0.3") and
                       has_peer("s1", "shortcut-route", "172.16.2.0"))
            eventually(lambda: events.read_text().count(
                "route-up shortcut-route 172.16.2.0/24") > before)
            assert not state.exists(), "loaded Spoke snapshot was not consumed"
            ns("s1", "ping", "-c", "1", "-W", "2", "-I", "10.20.0.2", "172.16.2.1")

            stop("s1")
            snapshot = state.read_text()
            assert "cached gre-cache 10.20.0.3/32 192.0.2.14" in snapshot
            assert "shortcut-route gre-cache 172.16.2.0/24 10.20.0.3 - 0" in snapshot
            assert stat.S_IMODE(state.stat().st_mode) == 0o600

            before = events.read_text().count("route-up shortcut-route 172.16.2.0/24")
            start("s1")
            eventually(lambda: has_peer("s1", "cached", "10.20.0.3") and
                       has_peer("s1", "shortcut-route", "172.16.2.0"))
            eventually(lambda: events.read_text().count(
                "route-up shortcut-route 172.16.2.0/24") > before)
            assert not state.exists(), "loaded Spoke snapshot was not consumed"
            ns("s1", "ping", "-c", "1", "-W", "2", "-I", "10.20.0.2", "172.16.2.1")

            # Expired and malformed snapshots are consumed without restoring peers.
            stop("s1")
            state.write_text(
                "OPENNHRP-PEER-CACHE 1\n"
                "dynamic gre-cache 10.20.0.76/32 192.0.2.76 - 1400 1\n"
                "cached gre-cache 10.20.0.77/32 192.0.2.77 - 1400 1\n"
                "shortcut-route gre-cache 172.16.77.0/24 10.20.0.77 - 0 1\n")
            state.chmod(0o600)
            start("s1")
            assert not has_peer("s1", "dynamic", "10.20.0.76")
            assert not has_peer("s1", "cached", "10.20.0.77")
            assert not has_peer("s1", "shortcut-route", "172.16.77.0")
            assert not state.exists()
            stop("s1")
            state.write_text("OPENNHRP-PEER-CACHE 1\ncached truncated\n")
            state.chmod(0o600)
            start("s1")
            assert not state.exists()
            stop("s1")

            expires = int(time.time()) + 60
            state.write_text(
                "OPENNHRP-PEER-CACHE 1\n"
                f"cached missing0 10.20.0.78/32 192.0.2.78 - 1400 {expires}\n"
                f"cached uplink 10.20.0.79/32 192.0.2.79 - 1400 {expires}\n"
                f"dynamic gre-cache 10.20.0.1/24 192.0.2.80 - 1400 {expires}\n"
                f"cached gre-cache 10.20.0.2/32 192.0.2.81 - 1400 {expires}\n")
            state.chmod(0o600)
            start("s1")
            for address in ("10.20.0.78", "10.20.0.79", "10.20.0.1", "10.20.0.2"):
                assert not has_peer("s1", "cached", address)
                assert not has_peer("s1", "dynamic", address)
            assert not state.exists()
            stop("s1")

            state.write_text("OPENNHRP-PEER-CACHE 9\n")
            state.chmod(0o600)
            start("s1")
            assert not state.exists()

            print("PASS: Hub legacy and Spoke learned peer caches survive graceful restart")
        except Exception:
            for log in work.glob("*.log"):
                print(f"--- {log.name} ---\n{log.read_text()[-3000:]}", file=sys.stderr)
            raise
        finally:
            for process in processes.values():
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
            for namespace in reversed(namespaces):
                run("ip", "netns", "del", namespace)


if __name__ == "__main__":
    main()
