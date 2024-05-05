#!/usr/bin/env sage
import sys
import ecdsa
import binascii
import hashlib
import base64

from ecdsa.util import sigencode_der, sigdecode_der
from ecdsa import SigningKey
from ecdsa import VerifyingKey

from sage.all import *

with open('./recovered_private.ec.pem','r') as f:
    priv_key_pem = f.read()
priv_key = SigningKey.from_pem(priv_key_pem.strip())
curve_order = priv_key.curve.order

with open('./payload.bin','rb') as f:
    payload = f.read()

sig = priv_key.sign(payload, sigencode=sigencode_der, hashfunc = hashlib.sha256)
ro,so = sigdecode_der(sig, curve_order)
print('ro=',hex(ro))
print('so=',hex(so))

'''
ro_s = hex(ro)[2:]
so_s = hex(so)[2:]

sig = base64.b64encode(ro_s.encode('latin-1')) + b'.' + base64.b64encode(so_s.encode('latin-1'))
'''

with open('./payload.sig','w') as f:
    f.write(base64.b64encode(sig).decode('latin-1'))





