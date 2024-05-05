from pwn import *
import sys

import chess
import chess.syzygy
from chess import Piece
import random

import IPython

context.local(log_level = 'silent')

tablebase = chess.syzygy.open_tablebase("tables/")


HOST = os.environ.get("HOST", 'localhost')
PORT = int(os.environ.get("PORT",5555))
TICKET = os.environ.get("TICKET")
p = remote(HOST, PORT)
if TICKET:
    p.readuntil('Ticket please: ')
    p.sendline(TICKET.encode("latin-1"))
context.clear(log_level='warn')


AITYPE = random.randint(0,1)
print("==========")
if AITYPE:
    print("best")
else:
    print("random")


def black_ai_random(b):
    #IPython.embed()
    minv = -1000
    ml = list(b.legal_moves)
    print("->",len(ml))
    print(ml)
    rmi = random.randrange(0,len(ml))
    m = ml[rmi]
    return m


def black_ai_best(b):
    #IPython.embed()
    minv = -1000
    print("->",len(list(b.legal_moves)))
    for m in b.legal_moves:
        b.push(m)
        probe = tablebase.probe_dtz(b)
        print(m, probe)
        if probe > minv and probe != 0:
            minv = probe
            cmove = m
        b.pop()
    return cmove

#Su0dsTyX5Y

import hashlib
import random
import string

NM = 10817184 #10822184-5000 ###


def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def sha256_to_integer(input_string):
    """Compute SHA-256 hash of the input string and convert it to an integer."""
    # Encode the string into bytes
    encoded_string = input_string.encode()

    # Compute the SHA-256 hash
    hash_object = hashlib.sha256(encoded_string)

    # Get the hexadecimal representation of the hash
    hex_hash = hash_object.hexdigest()

    # Convert the hexadecimal hash to an integer
    return int(hex_hash, 16)

def find_string_matching_hash():
    """Attempt to find a string whose SHA-256 hash, as integer, matches the target hash."""
    while True:
        # Generate a random string
        random_string = generate_random_string()

        # Get the integer hash of the string
        hash_as_integer = sha256_to_integer(random_string)

        # Check if the hash matches the target
        if hash_as_integer%25000001 < NM:
            return random_string, hash_as_integer


def cc_to_board(cc):
    b = chess.Board()
    b.clear()
    b.turn=chess.WHITE
    p = Piece(chess.KING, chess.WHITE)
    b.set_piece_at(cc[0],p)
    p = Piece(chess.KNIGHT, chess.WHITE)
    b.set_piece_at(cc[1],p)
    p = Piece(chess.BISHOP, chess.WHITE)
    b.set_piece_at(cc[2],p)
    p = Piece(chess.KING, chess.BLACK)
    b.set_piece_at(cc[3],p)
    b.turn = chess.WHITE
    return b


def str_to_board(lr):
    #print(lr)
    pieces = [b"K",b"N",b"B",b"k"]
    cc = [-1,-1,-1,-1]
    #print("===",lr)
    for i in range(8):
        for j in range(len(pieces)):
            if pieces[j] in lr[i]:
                cc[j] = (7-i)*8 + (lr[i].index(pieces[j])//2)

    return(cc_to_board(cc))


res = find_string_matching_hash()
print(res)
seeds = res[0].encode("utf-8")
#seeds = b"Su0dsTyX5Y" #


v = p.recvline()
print(v)
#import time; time.sleep(200)

v = p.recvuntil(b"Seed?\n")
print(v)
p.send(seeds+b"\n")

resh = []
tt = 30
mlen = 0
while True:
    res = p.recvline(timeout=tt)
    resh.append(res)
    if res == b"":
        break
    print(res.decode("utf-8"), end="")
    if b"harder" in res:
        tt = 90
    else:
        tt = 30
    if not res.endswith(b"Your move?\n"):
        continue

    mlen+=1
    b = str_to_board(resh[-9:])
    b.turn = chess.BLACK

    print("---")
    print(b)
    print("mlen:",mlen)
    print("---")

    if AITYPE:
        move = black_ai_best(b)
    else:
        move = black_ai_random(b)
    smove = str(move.from_square).encode("utf-8")+b" "+str(move.to_square).encode("utf-8")
    print(smove)
    #p.recvline()
    p.send(smove+b"\n")
    






