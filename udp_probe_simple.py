#!/usr/bin/env python3
# udp_probe_simple.py
import socket, sys, time

def udp_probe(host, port, payload=b"\x00", timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        start = time.time()
        s.sendto(payload, (host, port))
        data, addr = s.recvfrom(4096)
        elapsed = time.time() - start
        return {"host": host, "port": port, "reply": data[:200].hex() if isinstance(data, bytes) else str(data), "elapsed": elapsed}
    except socket.timeout:
        return {"host": host, "port": port, "reply": None, "elapsed": None}
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python udp_probe_simple.py <host> <port> [hex_payload]")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    payload = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b"\x00"
    print(udp_probe(host, port, payload))
