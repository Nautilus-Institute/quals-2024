import chess as c
from chess import Piece
import random
import sys
import hashlib
import struct
import subprocess

#import IPython

NM = 10817184 #10822184-5000 ###

buf = None


def cc_to_board(cc):
    b = c.Board()
    b.clear()
    b.turn=c.WHITE
    p = Piece(c.KING, c.WHITE)
    b.set_piece_at(cc[0],p)
    p = Piece(c.KNIGHT, c.WHITE)
    b.set_piece_at(cc[1],p)
    p = Piece(c.BISHOP, c.WHITE)
    b.set_piece_at(cc[2],p)
    p = Piece(c.KING, c.BLACK)
    b.set_piece_at(cc[3],p)
    b.turn = c.WHITE
    return b


def board_to_cc(b):
    n = len(bin(b.knights))-3
    s = len(bin(b.bishops))-3
    k1 = len(bin(b.occupied_co[1] & b.kings))-3
    k2 = len(bin(b.occupied_co[0] & b.kings))-3
    return (k1,n,s,k2)


def bai(b):
    while True:
        print("Your move?")
        tstr = input()
        tstr = tstr.strip()
        splitt = tstr.split(" ")
        x = int(splitt[0])
        y = int(splitt[1])
        move = c.Move(x,y)
        if b.is_legal(move):
            break
    print("You moved:",x,y)
    return move


def wai(b):
    cc = board_to_cc(b)
    for i in range(0, len(buf), 6):
        ut = struct.unpack('4B', buf[i:i+4])
        if cc == ut:
            x,y = struct.unpack('2B', buf[i+4:i+6])
            break
    else:
        print("Thinking harder...")
        args = ["./thinkingharder"]
        for i in cc:
            args.append(str(i))
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res = p.communicate()
        x,y = tuple([int(e) for e in res[0].strip().split()])

    move = c.Move(x,y)
    print("AI moved:",x,y)
    return move


def ist(b):
    #50 & threefold
    if b.can_claim_draw() or b.is_stalemate() or b.is_insufficient_material():
        return True


def p(b, wai_f, bai_f):
    move = wai_f(b)
    b.push(move)
    print(b)
    if ist(b):
        return -1
    elif b.is_checkmate():
        return 1
    move = bai_f(b)
    b.push(move)
    print(b)
    if ist(b):
        return -1
    elif b.is_checkmate():
        return 1
    return 0


def main():
    global buf

    cc = open(__file__,"rb").read()
    h=hashlib.md5()
    h.update(cc)
    v1 = h.hexdigest()[:4]
    cc = open("./thinkingharder","rb").read()
    h=hashlib.md5()
    h.update(cc)
    v2 = h.hexdigest()[:4]

    print("Welcome to hikarrru v"+v1+v2+"!")
    print("Seed?")

    tstr = input()
    tstr = tstr.strip()
    if len(tstr)<1 or len(tstr)>20:
        print("Invalid")
        return -1

    encoded_string = tstr.encode()
    hash_object = hashlib.sha256(encoded_string)
    hex_hash = hash_object.hexdigest()
    seedi = int(hex_hash, 16)

    seed = seedi % 25000001
    if seed >= NM:
        print("Invalid")
        return -1

    #with open("xy_python.pickle", "rb") as fd:
    #    bm = pickle.load(fd)


    buf = open("xy_python.bin", "rb").read()
    assert len(buf) == NM*6
    
    #IPython.embed()

    ut = struct.unpack('6B', buf[seed*6:seed*6+6])
    ot = (ut[:4], ut[4:])
    cc = ot[0]
    b = cc_to_board(cc)
    #print(cc)

    while True:
        print("===============")
        print(b)
        res = p(b, wai, bai)
        if res !=0:
            if res != 1:
                print("Congratulations, you didn't loose...")
                cc2 = board_to_cc(b)
                if cc2[3] == 61 and cc2[0] == 44:
                    print("This is the flag:", open("/flag", "rb").read())
                    return 0
                else:
                    print("But Our Flag is in Another Castle!")
                    return 0
            else:
                print("Chess is hard!")
                return 0


if __name__ == "__main__":
    sys.exit(main())

    #import IPython; IPython.embed()


