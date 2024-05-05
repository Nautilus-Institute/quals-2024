#!/usr/bin/env sage
import sys
import ecdsa
import binascii
import hashlib
import base64

from sage.all import *

from ecdsa.util import sigencode_der, sigdecode_der
from ecdsa import SigningKey
from ecdsa import VerifyingKey

with open('./public.ec.pem','r') as f:
    pub_key_pem = f.read()
public_key = VerifyingKey.from_pem(pub_key_pem.strip())
curve_order = public_key.curve.order

private_key = None

with open('./coldata1.bin', 'rb') as f:
    m1 = f.read()
with open('./coldata2.bin', 'rb') as f:
    m2 = f.read()

h1 = int(hashlib.sha256(m1).hexdigest(),base=16)
h2 = int(hashlib.sha256(m2).hexdigest(),base=16)

sig1 = base64.b64decode(sys.argv[1])
r1,s1 = sigdecode_der(sig1, curve_order)
sig2 = base64.b64decode(sys.argv[2])
r2,s2 = sigdecode_der(sig2, curve_order)

print('R1=',hex(r1))
print('S1=',hex(s1))

print('R2=',hex(r2))
print('S2=',hex(s2))

assert(r1 == r2)

'''
r1 = int(sys.argv[1], base=16)
s1 = int(sys.argv[2], base=16)

r2 = r1
s2 = int(sys.argv[3], base=16)
'''

tmp = r1*(s1-s2)
valinv = inverse_mod(tmp,curve_order)
#print('valinv',valinv)
rec_priv = (   (s2*h1-s1*h2) * (valinv)) % curve_order

print()
print('Recovered key:',rec_priv)
if private_key is not None:
    print("  Private key:",private_key.privkey.secret_multiplier)
    assert(private_key.privkey.secret_multiplier == rec_priv)

new_priv = SigningKey.from_secret_exponent(rec_priv, ecdsa.SECP256k1, hashfunc=hashlib.sha256)
assert(curve_order == new_priv.curve.order)

ppem = new_priv.to_pem().decode('latin-1')
print(ppem,'\n')
with open('recovered_private.ec.pem','w') as f:
    f.write(ppem)



