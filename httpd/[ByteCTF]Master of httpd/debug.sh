#!/bin/sh
sudo killall qemu-aarch64-static
sudo chroot ./ ./qemu-aarch64-static -L /lib -g 1234 ./mini_httpd_patched -C ./mini_httpd.conf -D
