#!/usr/bin/env python3
# lab4-2_scan.py

import socket, argparse, concurrent.futures, json, time

def probe_tcp(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return (port, True, None)
    except socket.timeout:
        return (port, False, "timeout")
    except ConnectionRefusedError:
        return (port, False, "refused")
    except Exception as e:
        return (port, False, str(e))

def parse_port_spec(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-",1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def scan_host(host, ports, workers, timeout):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(probe_tcp, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    return sorted(results, key=lambda x: x[0])

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--ports", default="1-1024")
    p.add_argument("--workers", type=int, default=50)
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--out", default="scan_results.json")
    args = p.parse_args()

    ports = parse_port_spec(args.ports)
    start = time.time()
    res = scan_host(args.host, ports, args.workers, args.timeout)
    elapsed = time.time() - start
    open_ports = [r for r in res if r[1]]
    print(open_ports)
    print(f"Scan complete in {elapsed:.2f}s — {len(open_ports)} open ports found")
    output = {"host": args.host, "elapsed": elapsed, "results": []}
    for port, open_, reason in res:
        output["results"].append({"port": port, "open": open_, "reason": reason})
    with open(args.out, "w") as fh:
        json.dump(output, fh, indent=2)
    print(f"Wrote results to {args.out}")