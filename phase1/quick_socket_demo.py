# quick_socket_demo.py
import socket, sys, time

host = "scanme.nmap.org"
port = 22  # try different ports

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)  # 3 second timeout
start = time.time()
try:
    s.connect((host, port))
    print(f"Connected to {host}:{port}")
    s.close()
except socket.timeout:
    print("Connection timed out")
except socket.error as e:
    print(f"Socket error: {e}")
finally:
    print(f"Elapsed: {time.time()-start:.2f}s")