from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes
import json

r = remote('34.146.137.8', 11223)
# r = remote('127.0.0.1', 11223)
AES_IV_HEX = "5f885849eadbc8c7bce244f8548a443f"
aes_iv = bytes.fromhex(AES_IV_HEX)

# initial message
msg = json.loads(r.recvline())

nonce = msg['nonce']
ct = bytes.fromhex(msg['ct'])

## arbitrary decryption oracle
init_ctr = 2
m = b''
for i in range(1, 18):
    print(f'finding block : {i}')
    counter = bytes.fromhex(nonce) + long_to_bytes(init_ctr + i, 4)

    ciphertext = counter + b'\x00'* 256
    r.sendline(ciphertext.hex())
    x = bytes.fromhex(json.loads(r.recvline())['ret'])[16:32]
    block = strxor(x, ct[16 * (i):16 * (i+1)])[:14] + b'\x00' * 2
    if i == 17:
        m += block[:13]
        break
    intended_pt = counter
    intended_ct = strxor(block, ct[16 * (i):16 * (i+1)])
    query = b''
    for j in range(65536):
        query += intended_ct[:14] + long_to_bytes(j, 2)
        if len(query) == 512:
            r.send(query.hex())
            ret = bytes.fromhex(json.loads(r.recvline())['ret'])
            for idx in range(32):
                if idx == 0:
                    iv = aes_iv
                else:
                    iv = query[16 * (idx - 1):16 * (idx)]
                pt = strxor(iv, ret[16 * (idx):16 * (idx + 1)])
                if pt == intended_pt:
                    m += strxor(query[16 * idx:16 * (idx + 1)], ct[16 * (i):16 * (i+1)])
                    print(m)
                    break
            query = b''
        if len(m) == 16 * (i):
            break
    if len(m) != 16 * (i):
        print('error')
        exit()
m = m[len('ion code is..'):]
print(m)
r.sendline(m.hex())
r.interactive()
