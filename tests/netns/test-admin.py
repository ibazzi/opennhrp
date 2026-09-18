#!/usr/bin/env python3
"""sudo python3 tests/netns/test-admin.py (after make compile)."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.check_output([str(a) for a in args], text=True, stderr=subprocess.STDOUT)


def main():
    assert os.geteuid() == 0, "run as root"
    namespace = f"onhrp-admin-{os.getpid()}"
    process = None
    run("ip", "netns", "add", namespace)
    with tempfile.TemporaryDirectory(prefix="opennhrp-admin-") as directory:
        work = Path(directory)
        address = str(work / "admin.sock")

        def ns(*args):
            return run("ip", "netns", "exec", namespace, *args)

        def connect(command):
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(10)
            client.connect(address)
            client.sendall(command)
            return client

        def receive(client, slow=False):
            result = bytearray()
            while True:
                data = client.recv(4096 if slow else 65536)
                if not data:
                    return bytes(result)
                result.extend(data)
                if slow:
                    time.sleep(.002)

        def ctl(command):
            with connect(command + b"\n") as client:
                client.shutdown(socket.SHUT_WR)
                return receive(client)

        try:
            ns("ip", "link", "set", "lo", "up")
            ns("ip", "tunnel", "add", "gre-admin", "mode", "gre", "key", "1020")
            ns("ip", "link", "set", "gre-admin", "up")
            ns("ip", "addr", "add", "10.20.0.1/24", "dev", "gre-admin")
            (work / "state").mkdir(mode=0o700)
            (work / "config").write_text("interface gre-admin\n route-table 100\n")
            with (work / "daemon.log").open("w") as log:
                process = subprocess.Popen([
                    "ip", "netns", "exec", namespace, str(REPO / "build/nhrp/opennhrp"),
                    "-a", address, "-H", str(work / "state"), "-c", str(work / "config"),
                    "-s", "/bin/true", "-p", str(work / "pid")],
                    stdout=log, stderr=log, start_new_session=True)
            for _ in range(100):
                if Path(address).exists():
                    break
                assert process.poll() is None
                time.sleep(.05)
            # Fragmented commands must append rather than overwrite the prefix.
            with connect(b"inter") as client:
                time.sleep(.05)
                client.sendall(b"face sh")
                time.sleep(.05)
                client.sendall(b"ow\n")
                client.shutdown(socket.SHUT_WR)
                assert b"Interface: gre-admin" in receive(client)

            routes = [f"172.20.{i // 256}.{i % 256}/32" for i in range(4000)]
            batch = work / "routes"
            # Pace route notifications: this test targets admin backpressure,
            # not the unrelated kernel Netlink receive-buffer capacity.
            for offset in range(0, len(routes), 100):
                batch.write_text("".join(f"route add {ip} dev gre-admin table 100\n"
                                         for ip in routes[offset:offset + 100]))
                ns("ip", "-batch", batch)
                for _ in range(100):
                    if ctl(b"route show").count(b"Type: local-route\n") == offset + 100:
                        break
                    time.sleep(.01)
                else:
                    raise AssertionError("route notifications did not converge")
            for _ in range(200):
                expected = ctl(b"route show")
                if expected.count(b"Type: local-route\n") == len(routes):
                    break
                time.sleep(.05)
            assert expected.count(b"Type: local-route\n") == len(routes)
            assert len(expected) > 256 * 1024
            with connect(b"route show\n") as slow:
                slow.shutdown(socket.SHUT_WR)
                time.sleep(.2)
                before = time.monotonic()
                assert b"Status: ok" in ctl(b"interface show")
                assert time.monotonic() - before < 2, "slow reader blocked control requests"
                assert receive(slow, True) == expected
            # Mutate lists while a dump is backpressured; output must terminate safely.
            with connect(b"route show\n") as slow:
                time.sleep(.2)
                for offset in range(0, 2000, 100):
                    batch.write_text("".join(f"route del {ip} dev gre-admin table 100\n"
                                             for ip in routes[offset:offset + 100]))
                    ns("ip", "-batch", batch)
                    time.sleep(.01)
                ns("ip", "route", "add", "172.21.0.1/32", "dev", "gre-admin", "table", "100")
                result = receive(slow, True)
                entries = [line for line in result.splitlines() if line.startswith(b"Protocol-Address:")]
                assert len(entries) == len(set(entries))
            with connect(b"route show\n"):
                pass  # Abandoned output cannot terminate the daemon through SIGPIPE.
            with connect(b"ha monitor\n") as monitor:
                assert monitor.recv(16384)
            # An incomplete command is discarded after ten seconds without progress.
            with connect(b"route") as stalled:
                stalled.settimeout(12)
                assert stalled.recv(1) == b""
            assert b"Status: ok" in ctl(b"show")
            assert process.poll() is None
            print("PASS: admin fragmented commands, half-close, 4000-route slow dump, mutation, monitor, timeout and responsiveness")
        except Exception:
            print((work / "daemon.log").read_text()[-4000:])
            raise
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
            run("ip", "netns", "del", namespace)


if __name__ == "__main__":
    main()
