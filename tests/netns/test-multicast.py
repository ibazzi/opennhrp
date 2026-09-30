#!/usr/bin/env python3
"""Verify GRE multicast reaches exactly the selected Hub, including fragments."""
import json
import subprocess
import sys

sender, source, expected, *hubs = sys.argv[1:]
group, port = "239.192.0.1", 31020
payloads = [b"opennhrp-multicast", b"opennhrp-multicast-large" * 100]
receiver_code = """
import json, socket, struct, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", %d))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(%r) + bytes(4) +
                struct.pack("=i", socket.if_nametoindex("gre-ha")))
sock.settimeout(0.1)
print("ready", flush=True)
packets = []
end = time.monotonic() + 2
while time.monotonic() < end:
    try:
        packets.append(sock.recv(65535).hex())
    except socket.timeout:
        pass
print(json.dumps(packets))
""" % (port, group)
sender_code = """
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(%r))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
for payload in %r:
    sock.sendto(payload, (%r, %d))
""" % (source, payloads, group, port)

receivers = []
try:
    for hub in hubs:
        proc = subprocess.Popen(
            ["ip", "netns", "exec", hub, "python3", "-c", receiver_code],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        receivers.append((hub, proc))
        assert proc.stdout.readline().strip() == "ready", hub
    subprocess.run(
        ["ip", "netns", "exec", sender, "python3", "-c", sender_code],
        check=True, timeout=5,
    )
    for hub, proc in receivers:
        output, error = proc.communicate(timeout=5)
        assert proc.returncode == 0, (hub, error)
        packets = json.loads(output)
        wanted = [payload.hex() for payload in payloads] if hub == expected else []
        assert sorted(packets) == sorted(wanted), (hub, [len(p) // 2 for p in packets])
    print(f"multicast from {sender} reached only {expected}, without duplicates")
finally:
    for _, proc in receivers:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
