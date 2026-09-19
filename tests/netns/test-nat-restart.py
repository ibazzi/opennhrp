#!/usr/bin/env python3
"""sudo python3 tests/netns/test-nat-restart.py (after make compile)."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("OPENNHRP_TEST_BIN", REPO / "build/nhrp"))


def run(*args, **kwargs):
    return subprocess.check_output([str(a) for a in args], stderr=subprocess.STDOUT,
                                   text=True, **kwargs)


def main():
    assert os.geteuid() == 0, "run as root"
    prefix = f"onhrp-nat-{os.getpid()}"
    processes, namespaces = {}, []
    with tempfile.TemporaryDirectory(prefix="opennhrp-nat-") as directory:
        work = Path(directory)

        def ns(node, *args):
            return run("ip", "netns", "exec", f"{prefix}-{node}", *args)

        def ctl(node, command):
            result = run(BIN / "opennhrpctl", "-a", work / f"{node}.sock", command)
            assert "Status: ok" in result, result
            return result

        def eventually(check, timeout=20):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    if check():
                        return
                except (subprocess.CalledProcessError, OSError, ValueError, KeyError):
                    pass
                time.sleep(.1)
            raise AssertionError("condition timed out")

        def start(node):
            (work / f"{node}.sock").unlink(missing_ok=True)
            with (work / f"{node}.log").open("a") as log:
                processes[node] = subprocess.Popen([
                    "ip", "netns", "exec", f"{prefix}-{node}",
                    str(BIN / "opennhrp"), "-a", str(work / f"{node}.sock"),
                    "-H", str(work / f"{node}-state"), "-c", str(work / f"{node}.conf"),
                    "-p", str(work / f"{node}.pid"), "-s", "/bin/true", "-v"],
                    stdout=log, stderr=log, start_new_session=True)
            eventually(lambda: (work / f"{node}.sock").exists())

        def stop(node):
            process = processes.pop(node)
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=10)
            assert process.returncode == 0

        def ready():
            raw = ctl("s", "ha show format json")
            data = json.loads(raw[raw.index("{"):])
            return data.get("coordinator_state") == "running" and any(
                c["active"] and c["registered"] and c["ready"] and
                c["selected_address"] == "192.0.2.21" for c in data.get("candidates", []))

        try:
            for node in ("h", "s"):
                name = f"{prefix}-{node}"
                run("ip", "netns", "add", name)
                namespaces.append(name)
                ns(node, "ip", "link", "set", "lo", "up")
                (work / f"{node}-state").mkdir(mode=0o700)
            ns("h", "ip", "link", "add", "uplink", "type", "veth", "peer", "name",
               "uplink", "netns", f"{prefix}-s")
            for node, address in (("h", "192.0.2.11"), ("s", "192.0.2.13")):
                ns(node, "ip", "link", "set", "uplink", "up")
                ns(node, "ip", "addr", "add", address + "/24", "dev", "uplink")
                ns(node, "ip", "tunnel", "add", "gre-ha", "mode", "gre", "key", "1020", "ttl", "64")
                ns(node, "ip", "link", "set", "gre-ha", "mtu", "1400", "up")
                ns(node, "ip", "addr", "add", f"10.20.0.{1 if node == 'h' else 2}/24", "dev", "gre-ha")
                ns(node, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0",
                   "net.ipv4.conf.uplink.rp_filter=0", "net.ipv4.conf.gre-ha.rp_filter=0")
            ns("h", "ip", "addr", "add", "192.0.2.21/24", "dev", "uplink")
            ns("s", "ip", "addr", "add", "192.0.2.23/24", "dev", "uplink")
            ns("h", "ip", "route", "replace", "192.0.2.23/32", "dev", "uplink",
               "src", "192.0.2.21")
            ns("s", "iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "47",
               "-d", "192.0.2.21", "-j", "SNAT", "--to-source", "192.0.2.23")
            (work / "h.conf").write_text(
                "interface gre-ha\n enable-ha member-id hub advertise 192.0.2.11 advertise 192.0.2.21\n")
            public_config = "interface gre-ha\n holding-time 120\n map 10.20.0.1 192.0.2.21 register\n"
            private_config = public_config.replace("192.0.2.21", "192.0.2.11")
            (work / "s.conf").write_text(public_config)
            start("h")
            start("s")
            eventually(ready)
            before = ctl("h", "show protocol 10.20.0.2")
            assert "NBMA-Address: 192.0.2.23" in before, before
            assert "NBMA-NAT-OA-Address: 192.0.2.13" in before, before
            stop("s")
            # Hub keeps the public NAT binding while the Spoke boots privately.
            (work / "s.conf").write_text(private_config)
            start("s")
            eventually(ready)
            assert "unique address already registered" in (work / "s.log").read_text()
            assert (work / "s.conf").read_text() == private_config
            assert "NBMA-Address: 192.0.2.23" in ctl("h", "show protocol 10.20.0.2")
            ns("s", "ping", "-c", "3", "-W", "2", "10.20.0.1")
            stop("s")
            start("s")
            eventually(ready)
            # Background probes must not restore the rejected private preference.
            for _ in range(30):
                time.sleep(.2)
                assert ready(), "recovered NAT endpoint did not remain ready"
            # A different original NBMA must not take over through either path.
            stop("s")
            ns("s", "ip", "addr", "add", "192.0.2.14/24", "dev", "uplink")
            for endpoint in ("192.0.2.11", "192.0.2.21"):
                ns("s", "ip", "route", "replace", endpoint + "/32", "dev", "uplink", "src", "192.0.2.14")
            log_offset = (work / "s.log").stat().st_size
            start("s")
            def collision_discovered():
                raw = ctl("s", "ha show format json")
                data = json.loads(raw[raw.index("{"):])
                return data.get("hub_list_generation", 0) > 0
            eventually(collision_discovered)
            time.sleep(3)
            raw = ctl("s", "ha show format json")
            data = json.loads(raw[raw.index("{"):])
            assert data["active_member"] is None, data
            assert all(not c["registered"] for c in data["candidates"]), data
            assert "unique address already registered" in (work / "s.log").read_text()[log_offset:]
            binding = ctl("h", "show protocol 10.20.0.2")
            assert "NBMA-Address: 192.0.2.23" in binding, binding
            assert "NBMA-NAT-OA-Address: 192.0.2.13" in binding, binding
            print("PASS: NAT restart recovery, repeated restart, and conflicting client exclusion")
        except Exception:
            if "s" in processes:
                print(ctl("s", "ha show format json"))
            for log in work.glob("*.log"):
                content = log.read_text()
                print(f"--- {log.name} ---\n{content[:8000]}\n...\n{content[-6000:]}")
            raise
        finally:
            for process in processes.values():
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
            for name in reversed(namespaces):
                run("ip", "netns", "del", name)


if __name__ == "__main__":
    main()
