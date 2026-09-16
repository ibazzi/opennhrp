#!/usr/bin/env python3
"""sudo python3 tests/netns/test-legacy-spoke.py (after make compile).

Exercise real registration packets and kernel GRE forwarding. The packet sender
models legacy wire behavior; it is not an actual old OpenNHRP binary. Coordinators
are paused so role and replication transitions can be tested deterministically.
"""
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.check_output([str(a) for a in args], stderr=subprocess.STDOUT, text=True)


def send_registration(hub, mode, addresses):
    member = b"bootstrap"
    ha = struct.pack("!BBHI", 2, 1, len(member), 1) + member
    invalid = mode.startswith("invalid")
    if invalid:
        ha = ha[:5]
    vendor = mode.endswith("vendor")
    if vendor:
        ha = b"\xae\xde\x48ONHRP" + ha
    extensions = b""
    if mode != "legacy":
        extensions = struct.pack("!HH", 8 if vendor else 0x3801, len(ha)) + ha
    extensions += b"\0\0\0\0"
    ip = socket.inet_aton
    body = ip("192.0.2.13") + ip(addresses[0]) + ip("10.20.0.1")
    for address in addresses:
        body += struct.pack("!BBHHHBBBB", 0, 32, 0, 1400, 120, 4, 0, 4, 0)
        body += ip("192.0.2.13") + ip(address)
    request_id = os.getpid()
    header = struct.pack("!HH5sBHHHBBBBBBHI", 1, 0x800, b"\0" * 5, 16,
                         28 + len(body) + len(extensions), 0, 28 + len(body),
                         1, 3, 4, 0, 4, 4, 0x8000, request_id)
    packet = bytearray(header + body + extensions)
    padded = packet + b"\0" if len(packet) % 2 else packet
    checksum = sum(struct.unpack(f"!{len(padded)//2}H", padded))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    struct.pack_into("!H", packet, 12, ~checksum & 0xffff)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_GRE) as sock:
        sock.bind(("192.0.2.13", 0))
        sock.settimeout(2)
        sock.sendto(struct.pack("!HHI", 0x2000, 0x2001, 1020) + packet, (hub, 0))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                reply = sock.recv(65535)
            except socket.timeout:
                assert invalid, "Registration Reply timed out"
                return
            reply = reply[(reply[0] & 15) * 4 + 8:]
            if len(reply) < 40 or reply[17] != 4 or struct.unpack_from("!I", reply, 24)[0] != request_id:
                continue
            assert not invalid, "invalid HA registration was accepted"
            offset = 28 + reply[18] + reply[19] + reply[20] + reply[21]
            for _ in addresses:
                assert reply[offset] == 0, f"registration rejected: {reply.hex()}"
                offset += 12 + reply[offset + 8] + reply[offset + 9] + reply[offset + 10]
            return
        raise AssertionError("no matching Registration Reply")


def main():
    assert os.geteuid() == 0, "run as root"
    prefix = f"onhrp-legacy-{os.getpid()}"
    namespaces, processes, paused = [], [], []
    with tempfile.TemporaryDirectory(prefix="opennhrp-legacy-") as directory:
        work = Path(directory)

        def ns(node, *args):
            return run("ip", "netns", "exec", f"{prefix}-{node}", *args)

        def ctl(node, *args):
            result = run(REPO / "nhrp/opennhrpctl", "-a", work / f"{node}.sock", *args)
            assert "Status: failed" not in result, result
            return result

        def role(node, name, term):
            ctl(node, "ha hub role interface gre-ha role", name, "term", term, "index 0")

        def register(node, mode, *addresses):
            ns("sp", sys.executable, __file__, "--send", f"192.0.2.{11 if node == 'h1' else 12}", mode, *addresses)

        def snapshot(node):
            return ctl(node, "ha registration snapshot interface gre-ha")

        def present(node, address):
            return f"Protocol-Address: {address}" in ctl(node, "show")

        def eventually(check):
            for _ in range(100):
                if check():
                    return
                time.sleep(.05)
            raise AssertionError("condition timed out")

        def ping(node, address):
            eventually(lambda: present(node, address))
            # Model the spoke's configured Hub mapping for the return path.
            ns("sp", "ip", "neigh", "replace", "10.20.0.1", "lladdr",
               f"192.0.2.{11 if node == 'h1' else 12}", "nud", "permanent", "dev", "gre-ha")
            ns(node, "ping", "-c", "1", "-W", "2", "-I", "10.20.0.1", address)
            assert "192.0.2.13" in ns(node, "ip", "neigh", "show", "to", address, "dev", "gre-ha")

        def sync(node, address, term):
            ctl(node, "ha registration sync begin interface gre-ha term", term, "index 0")
            ctl(node, "ha registration sync apply interface gre-ha protocol", address,
                "nbma 192.0.2.13 mtu 1400 holding 120 flags 96 term", term, "index 0")
            ctl(node, "ha registration sync end interface gre-ha")

        try:
            for node in ("sp", "h1", "h2"):
                namespace = f"{prefix}-{node}"
                run("ip", "netns", "add", namespace)
                namespaces.append(namespace)
                ns(node, "ip", "link", "set", "lo", "up")
            ns("sp", "ip", "link", "add", "br0", "type", "bridge")
            ns("sp", "ip", "link", "set", "br0", "up")
            ns("sp", "ip", "addr", "add", "192.0.2.13/24", "dev", "br0")
            for node, suffix in (("h1", 11), ("h2", 12)):
                ns("sp", "ip", "link", "add", node, "type", "veth", "peer", "name", "uplink", "netns", f"{prefix}-{node}")
                ns("sp", "ip", "link", "set", node, "master", "br0")
                ns("sp", "ip", "link", "set", node, "up")
                ns(node, "ip", "link", "set", "uplink", "up")
                ns(node, "ip", "addr", "add", f"192.0.2.{suffix}/24", "dev", "uplink")
            for node in ("sp", "h1", "h2"):
                ns(node, "ip", "tunnel", "add", "gre-ha", "mode", "gre", "key", "1020", "ttl", "64")
                ns(node, "ip", "link", "set", "gre-ha", "mtu", "1400", "up")
                ns(node, "ip", "addr", "add", f"10.20.0.{2 if node == 'sp' else 1}/24", "dev", "gre-ha")
                ns(node, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.gre-ha.rp_filter=0")
            for last in range(200, 207):
                ns("sp", "ip", "addr", "add", f"10.20.0.{last}/32", "dev", "gre-ha")
            for node, suffix in (("h1", 11), ("h2", 12)):
                state = work / f"{node}-state"
                state.mkdir(mode=0o700)
                config = work / f"{node}.conf"
                config.write_text(f"interface gre-ha\n enable-ha member-id {node} advertise 192.0.2.{suffix}\n")
                with (work / f"{node}.log").open("w") as log:
                    process = subprocess.Popen(["ip", "netns", "exec", f"{prefix}-{node}",
                        str(REPO / "nhrp/opennhrp"), "-a", str(work / f"{node}.sock"),
                        "-H", str(state), "-c", str(config), "-s", "/bin/true", "-p", str(work / f"{node}.pid"), "-v"],
                        stdout=log, stderr=log, start_new_session=True)
                processes.append(process)
                eventually(lambda: (work / f"{node}.sock").exists())
                children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
                eventually(lambda: children.read_text().strip())
                for child in children.read_text().split():
                    os.kill(int(child), signal.SIGSTOP)
                    paused.append(int(child))
                role(node, "leader" if node == "h1" else "standby", 1000)

            register("h1", "legacy", "10.20.0.200", "10.20.0.201")
            register("h1", "ha", "10.20.0.202", "10.20.0.203")
            register("h1", "vendor", "10.20.0.204")
            register("h1", "invalid", "10.20.0.205")
            register("h1", "invalid-vendor", "10.20.0.205")
            assert not present("h1", "10.20.0.205")
            snap = snapshot("h1")
            for last in (200, 201):
                assert f"entry 10.20.0.{last} " not in snap
                ping("h1", f"10.20.0.{last}")
            for last in (202, 203, 204):
                assert f"entry 10.20.0.{last} " in snap
            register("h1", "legacy", "10.20.0.203")
            assert "entry 10.20.0.203 " not in snapshot("h1")
            sync("h2", "10.20.0.202/32", 1000)
            assert not present("h2", "10.20.0.202")
            role("h2", "follower", 1000)
            ping("h2", "10.20.0.202")
            role("h2", "standby", 1001)
            assert not present("h2", "10.20.0.202")
            role("h1", "standby", 1001)
            role("h2", "leader", 1001)
            assert not present("h1", "10.20.0.202")
            ping("h2", "10.20.0.202")
            register("h1", "legacy", "10.20.0.200", "10.20.0.201")
            register("h1", "legacy", "10.20.0.206")
            register("h1", "ha", "10.20.0.202")
            assert not present("h1", "10.20.0.202")
            register("h1", "legacy", "10.20.0.204")
            assert "entry 10.20.0.204 " not in snapshot("h1")
            for term in (1002, 1003, 1004):
                sync("h1", "10.20.0.204/32", term)
                assert "entry 10.20.0.204 " not in snapshot("h1")
                role("h1", "leader", term)
                sync("h1", "10.20.0.204/32", term)
                assert "entry 10.20.0.204 " not in snapshot("h1")
                ping("h1", "10.20.0.202")
                role("h1", "standby", term)
                for last in (200, 201, 203, 204, 206):
                    ping("h1", f"10.20.0.{last}")
            print("PASS: legacy/HA/Vendor/invalid/multiple CIE, renewal, sync, failover, failback, neighbors and GRE ping")
        except Exception:
            for log in work.glob("*.log"):
                print(f"--- {log.name} ---\n{log.read_text()[-12000:]}", file=sys.stderr)
            raise
        finally:
            for child in paused:
                try:
                    os.kill(child, signal.SIGCONT)
                except ProcessLookupError:
                    pass
            for process in processes:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)
            for namespace in reversed(namespaces):
                run("ip", "netns", "del", namespace)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--send":
        send_registration(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        main()
