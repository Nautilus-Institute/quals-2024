_A='./thinkingharder'
import chess as c
from chess import Piece
import random,sys,hashlib,struct,subprocess
NM=10817184
buf=None
def cc_to_board(cc):A=c.Board();A.clear();A.turn=c.WHITE;B=Piece(c.KING,c.WHITE);A.set_piece_at(cc[0],B);B=Piece(c.KNIGHT,c.WHITE);A.set_piece_at(cc[1],B);B=Piece(c.BISHOP,c.WHITE);A.set_piece_at(cc[2],B);B=Piece(c.KING,c.BLACK);A.set_piece_at(cc[3],B);A.turn=c.WHITE;return A
def board_to_cc(b):A=len(bin(b.knights))-3;B=len(bin(b.bishops))-3;C=len(bin(b.occupied_co[1]&b.kings))-3;D=len(bin(b.occupied_co[0]&b.kings))-3;return C,A,B,D
def bai(b):
	while True:
		print('Your move?');A=input();A=A.strip();B=A.split(' ');C=int(B[0]);D=int(B[1]);E=c.Move(C,D)
		if b.is_legal(E):break
	print('You moved:',C,D);return E
def wai(b):
	D=board_to_cc(b)
	for A in range(0,len(buf),6):
		F=struct.unpack('4B',buf[A:A+4])
		if D==F:B,C=struct.unpack('2B',buf[A+4:A+6]);break
	else:
		print('Thinking harder...');E=[_A]
		for A in D:E.append(str(A))
		G=subprocess.Popen(E,stdout=subprocess.PIPE,stderr=subprocess.PIPE);H=G.communicate();B,C=tuple([int(A)for A in H[0].strip().split()])
	I=c.Move(B,C);print('AI moved:',B,C);return I
def ist(b):
	if b.can_claim_draw()or b.is_stalemate()or b.is_insufficient_material():return True
def p(b,wai_f,bai_f):
	A=wai_f(b);b.push(A);print(b)
	if ist(b):return-1
	elif b.is_checkmate():return 1
	A=bai_f(b);b.push(A);print(b)
	if ist(b):return-1
	elif b.is_checkmate():return 1
	return 0
def main():
	J='Invalid';D='rb';global buf;A=open(__file__,D).read();B=hashlib.md5();B.update(A);K=B.hexdigest()[:4];A=open(_A,D).read();B=hashlib.md5();B.update(A);L=B.hexdigest()[:4];print('Welcome to hikarrru v'+K+L+'!');print('Seed?');C=input();C=C.strip()
	if len(C)<1 or len(C)>20:print(J);return-1
	M=C.encode();N=hashlib.sha256(M);O=N.hexdigest();P=int(O,16);E=P%25000001
	if E>=NM:print(J);return-1
	buf=open('xy_python.bin',D).read();G=struct.unpack('6B',buf[E*6:E*6+6]);Q=G[:4],G[4:];A=Q[0];F=cc_to_board(A)
	while True:
		print('===============');print(F);H=p(F,wai,bai)
		if H!=0:
			if H!=1:
				print("Congratulations, you didn't loose...");I=board_to_cc(F)
				if I[3]==61 and I[0]==44:print('This is the flag:',open('/flag',D).read());return 0
				else:print('But Our Flag is in Another Castle!');return 0
			else:print('Chess is hard!');return 0
if __name__=='__main__':sys.exit(main())