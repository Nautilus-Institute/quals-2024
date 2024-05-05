import os
import socket
import sys
import time
import struct

os.system('wat2wasm --no-check /opt/solve.wat -o /tmp/solve.wasm')
with open('/tmp/solve.wasm', 'rb') as fi:
    data = fi.read(-1)
blob = struct.pack('>H', len(data)) + data

HOST = os.environ["HOST"]
PORT = int(os.environ["PORT"])

TICKET = None if "TICKET" not in os.environ else os.environ["TICKET"]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

if TICKET is not None:
    sock.recv(len("Ticket please: "))
    sock.sendall((TICKET + "\n").encode("utf-8"))

time.sleep(1)

print(f'sending {len(blob)-2} bytes of wasm')

output = sock.recv(1024)
print(output)

sock.sendall(blob)

while True:
    tmp = sock.recv(1024)
    if len(tmp) == 0:
        print('eof')
        break
    output += tmp
    print(tmp.decode('utf8'))

if "flag{" in output.decode("utf-8"):
    print("PASS")
    sys.exit(0)
else:
    print("FAIL")
    sys.exit(1)
