#!/usr/bin/env python3
# lab4-2_probe.py
import socket, sys

def probe_tcp(host, port, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        s.close()
        return True, None
    except socket.timeout:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "refused"
    except socket.gaierror:
        return False, "name_error"
    except Exception as e:
        return False, str(e)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python lab4-2_probe.py <host> <port> [timeout]")
        sys.exit(1)
    host = sys.argv[1]
    port = sys.argv[2]
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 3.0
    open_, reason = probe_tcp(host, port, timeout)
    if open_:
        print(f"{host}:{port} is OPEN")
    else:
        print(f"{host}:{port} is CLOSED ({reason})")