import os
import sys
import socket
import threading
import subprocess

MAX_READ_BUFFER = 0x1000
SERVER_ADDR = ("0.0.0.0", 2333)

DEBUG_MODE = 0
DEBUG_GDB_PORT = 1234


def handler(cli_sock: socket.socket, cli_addr: tuple):
    #args = ["./httpd"]
    sub_p = subprocess.Popen("qemu-mips -L ./ ./qwbhttpd", shell=True, stdin=cli_sock.fileno(),
                             stdout=cli_sock.fileno(), stderr=sys.stdout.fileno())
    sub_p.wait()
    print("Connection closed:", cli_addr)
    cli_sock.close()


def main():
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv_sock.bind(SERVER_ADDR)
    serv_sock.listen(20)
    print("Server listent on:", SERVER_ADDR)

    while True:
        cli_sock, cli_addr = serv_sock.accept()
        print("Accept:", cli_addr)
        th = threading.Thread(target=handler, args=(cli_sock, cli_addr))
        th.setDaemon(True)
        th.start()


if __name__ == "__main__":
    main()
